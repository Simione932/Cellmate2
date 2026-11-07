cmake_minimum_required(VERSION 3.21)
project(cellmate2 C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(WIN32)
    # SimpleBLE's Windows backend is C++/WinRT, which requires coroutines.
    set(CMAKE_CXX_STANDARD 20)
endif()

include(FetchContent)

# SimpleCBLE (C API of SimpleBLE)
FetchContent_Declare(SimpleBLE
    GIT_REPOSITORY https://github.com/SimpleBLE/SimpleBLE.git
    GIT_TAG v1.3.0
)
FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
# curl built from the release tarball (static).
# SSL: LibreSSL on Windows (from the curl mingw bundle, shared with the app's
# own AES) so we need no Schannel code path; OpenSSL elsewhere.
if(WIN32)
    set(CRYPTO_BUNDLE ${CMAKE_SOURCE_DIR}/../third-party/curl-win/curl-8.23.0_8-win64-mingw)
    set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "" FORCE)
    # Root dir is mandatory: FindOpenSSL's MinGW branch re-runs find_library
    # when it is unset and clobbers the cached *_LIBRARY hints.
    set(OPENSSL_ROOT_DIR ${CRYPTO_BUNDLE} CACHE PATH "" FORCE)
    set(OPENSSL_INCLUDE_DIR ${CRYPTO_BUNDLE}/include CACHE PATH "" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY ${CRYPTO_BUNDLE}/lib/libcrypto.a CACHE FILEPATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY ${CRYPTO_BUNDLE}/lib/libssl.a CACHE FILEPATH "" FORCE)
    # FindOpenSSL accepts the bundle's LibreSSL (libssl/libcrypto, same API).
    set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
    # We only use libcurl; the curl CLI would need our fstat64 shim too.
    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    # Windows has no CA auto-detection; pin Mozilla's bundle at build time so
    # certificate verification works. Keep this file up to date (curl.se/ca).
    set(CURL_CA_BUNDLE ${CMAKE_SOURCE_DIR}/../third-party/cacert.pem CACHE STRING "" FORCE)
else()
    find_package(OpenSSL REQUIRED)
    set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
endif()
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
FetchContent_Declare(curl
    URL https://github.com/curl/curl/releases/download/curl-8_11_1/curl-8.11.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(SimpleBLE)
FetchContent_MakeAvailable(nlohmann_json)
FetchContent_MakeAvailable(curl)

add_subdirectory(${simpleble_SOURCE_DIR}/simplecble ${CMAKE_BINARY_DIR}/simplecble)
if(WIN32)
    # simplecble pins C++17, but its Windows (C++/WinRT) backend needs coroutines.
    set_target_properties(simpleble PROPERTIES CXX_STANDARD 20)
    # The C++/WinRT backend uses runtimeobject.dll; attach the import libs here
    # so they land after libsimpleble.a on the link line (order matters).
    target_link_libraries(simpleble PRIVATE runtimeobject windowsapp)
endif()

add_executable(cellmate2 src/main.cpp src/httpc.c src/shim_win.c)
target_link_libraries(cellmate2
    simplecble
    nlohmann_json::nlohmann_json
    libcurl_static
)
if(WIN32)
    # AES via the EVP API, using the same LibreSSL as curl (see above).
    target_include_directories(cellmate2 PRIVATE ${CRYPTO_BUNDLE}/include)
    target_link_libraries(cellmate2 ${CRYPTO_BUNDLE}/lib/libcrypto.a ws2_32 crypt32 bcrypt)
else()
    target_link_libraries(cellmate2 OpenSSL::Crypto)
endif()
