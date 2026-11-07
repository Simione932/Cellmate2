// cellmate2 — standalone controller for the QIUI cellmate II (Gen2Lock, typeId 4)
//
// Networking: closed backend appapi.qiuitoy.com (login + command minting).
//   Keys/IV recovered from qiui.apk (see ../notes.md):
//     API key  87dQ_P5F#9&K*G6b9&f%8!d&06@(c_*a
//     PWD key  10kB8mdiaWRxFkNQD8Xtb6fm>Cg5N_QX
//     TS key   LpyaN2dvT3CbxRNJ>^*kjjAsq=^e*cD5   (EncryptUtil.TIME_STAMP, toyUid field)
//     IV       3*1&f6O%6&Pa5d_8
//   Endpoints (all POST, body = base64(AES-CBC(key, compact-json)), "token" header):
//     login            api/feign/userInfo/login
//     device list      api/feign/toyUserBinding/getUserBindingToyDevices
//     token            api/feign/toyCellmateBluetooth/getToyToken
//     unlock           api/feign/toyBluetooth/unlockToy  {unLockType:"0", type:<toyRole>, toyUid}
//     lock             api/feign/toyCellmateBluetooth/toyCloseLock {toyUid}
//     clear-shock      api/feign/toyCellmateBluetooth/clearToyTimingElectricShock {toyUid}
//     clear-timed-unk  api/feign/toyCellmateBluetooth/clearToyUnlockTimingTime {toyUid}
//     shock            api/feign/toyElectricTimingRecord/saveElectricTimingRecord
//                      {electricShockTime, electricMode, shockVolt,
//                       beginElectricTime, toyUid}
//                      then /synchronizeElectricTimingRecord {toyUid} ->
//                      data[].lockCommand (b64(AES(CMD_KEY, 32-hex))) + reply
//     shock-now        api/feign/toyCellmateBluetooth/getToyShockImmediately
//                      {shockModel, shockVolt, toyUid} -> command straight to ae3b
//     decrypt reply    api/feign/toyCellmateBluetooth/decryBluetoothCommand
//                       {lockCommand:<32-hex>, toyUid:<TS-enc>}
//
// Bluetooth: SimpleBLE GATT client.
//   service 0000ae3a-0000-1000-8000-00805f9b34fb
//   write   0000ae3b (write command, 16 bytes)
//   notify  0000ae3c (16-byte replies, enabled via CCC 00002902)
//   Connect by CoreBluetooth UUID (the device rotates its advertisement
//   address; MACs from advertisements are NOT usable for API calls).
//
// Protocol: server mints 32-hex command -> write 16 bytes to ae3b ->
// 16-byte reply on ae3c -> hex -> decryBluetoothCommand -> {battery, commandCode}.
// commandCode: 01 token, 02 unlock, 03 lock, 06 clear timed unlock, 14 clear timed shock.
// Unlock/lock are gated on the device token having been delivered over BLE.

#include <simplecble/simplecble.h>

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <openssl/evp.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <map>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <optional>
#include <regex>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;

// ---------------------------------------------------------------- constants

static const std::string API_KEY = "87dQ_P5F#9&K*G6b9&f%8!d&06@(c_*a";
static const std::string PWD_KEY = "10kB8mdiaWRxFkNQD8Xtb6fm>Cg5N_QX";
static const std::string TS_KEY  = "LpyaN2dvT3CbxRNJ>^*kjjAsq=^e*cD5";
static const std::string BTA_KEY = "X7vuZ@NvjPtMmBF8bpWbbfrpYa3h11IB";  // BLUETOOTH_ADDRESS
static const std::string CMD_KEY = "VfttrWZYZ5QVUe>})C5x?oYWVewxVy!]";  // BLUETOOTH_COMMAND
static const std::string IV      = "3*1&f6O%6&Pa5d_8";

static const std::string SVC_UUID  = "0000ae3a-0000-1000-8000-00805f9b34fb";
static const std::string WR_UUID   = "0000ae3b-0000-1000-8000-00805f9b34fb";
static const std::string NT_UUID   = "0000ae3c-0000-1000-8000-00805f9b34fb";

static const std::string CONFIG_URL =
    "https://qiui-cn.oss-cn-shenzhen.aliyuncs.com/file/urlList/api.html";
static const std::string FALLBACK_BASE = "https://appapi.qiuitoy.com/";

// Captured working login payload (notes.md, logcat "登录发送的数据").
// passWord is a constant: AES with a fixed IV is deterministic.
// blackBox is single-use/session-scoped — recapture via phone logcat when
// logins start failing (override with QIUI_BLACKBOX).
static const std::string CAP_EMAIL    = "";
static const std::string CAP_PASSWD_B64 = "";
static const std::string CAP_BLACKBOX = "";
static const std::string CAP_PHONEID  = "";
// Manufacturer data (vendor 0x15F0) advertised by our board — stable per
// device, unlike the rotating CB UUID. The advertised NAME (QIUI104) is
// shared by all cellmate boards, so the mfr payload is the real
// discriminator. Capture with: cellmate2 - scan-dump
static const std::string CAP_MFR    = "097a1aa5ca0a34";

static const char* ENV_EMAIL    = "QIUI_EMAIL";
static const char* ENV_PASSWD   = "QIUI_PASSWORD";  // plain password, AES-enc'd at login
static const char* ENV_TOKEN    = "QIUI_TOKEN";     // captured session token — skips login
static const char* ENV_BLACKBOX = "QIUI_BLACKBOX";
static const char* ENV_PHONEID  = "QIUI_PHONEID";
static const char* ENV_UUID     = "QIUI_BLE_ID";  // advertised name, e.g. QIUI104
static const char* ENV_MFR      = "QIUI_BLE_MFR";  // mfr data hex filter

static std::string env_or(const char* name, const std::string& def) {
    if (const char* v = std::getenv(name)) return v;
    return def;
}

// Read a key from the captured-credentials file written by capture_login.py.
// Primary credential source; env vars / CAP_* remain as fallbacks. Returns ""
// for an absent file or field.
static std::string read_cred(const std::string& path, const std::string& key) {
    std::ifstream f(path);
    if (!f) return "";
    std::string line;
    while (std::getline(f, line)) {
        auto i = line.find('=');
        if (i == std::string::npos) continue;
        if (line.substr(0, i) == key) {
            std::string v = line.substr(i + 1);
            auto s = v.find_first_not_of(" \t\r\n");
            auto e = v.find_last_not_of(" \t\r\n");
            if (s == std::string::npos) return "";
            return v.substr(s, e - s + 1);
        }
    }
    return "";
}

// ---------------------------------------------------------------- crypto

static std::string b64_encode(const std::vector<uint8_t>& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t n = in[i] << 16;
        if (i + 1 < in.size()) n |= in[i + 1] << 8;
        if (i + 2 < in.size()) n |= in[i + 2];
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += (i + 1 < in.size()) ? tbl[(n >> 6) & 63] : '=';
        out += (i + 2 < in.size()) ? tbl[n & 63] : '=';
    }
    return out;
}

static std::vector<uint8_t> b64_decode(const std::string& in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((buf >> bits) & 0xFF);
        }
    }
    return out;
}

// AES-CBC, PKCS#7, 16/24/32-byte key. enc=true encrypt, false decrypt.
static std::vector<uint8_t> aes_cbc(const std::string& key, const std::string& iv,
                                    const std::vector<uint8_t>& in, bool enc) {
    std::vector<uint8_t> out;
    int len = 0, final_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(
        key.size() == 16 ? "AES-128-CBC" : key.size() == 24 ? "AES-192-CBC"
                                                             : "AES-256-CBC");
    int block = EVP_CIPHER_block_size(cipher);
    out.resize(enc ? in.size() + block : in.size());
    int ok = EVP_CipherInit_ex(ctx, cipher, nullptr,
                               reinterpret_cast<const uint8_t*>(key.data()),
                               reinterpret_cast<const uint8_t*>(iv.data()),
                               enc ? 1 : 0);
    if (ok == 1) ok = EVP_CipherUpdate(ctx, out.data(), &len, in.data(), (int)in.size());
    if (ok == 1) ok = EVP_CipherFinal_ex(ctx, out.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) throw std::runtime_error("AES-CBC failure");
    out.resize(len + final_len);
    return out;
}

static std::string aes_enc(const std::string& key, const std::string& data) {
    return b64_encode(aes_cbc(key, IV, std::vector<uint8_t>(data.begin(), data.end()), true));
}

static std::string aes_dec(const std::string& key, const std::string& b64) {
    auto pt = aes_cbc(key, IV, b64_decode(b64), false);
    return std::string(pt.begin(), pt.end());
}

// The device list's toyUid is itself b64(AES(TS_KEY, "<raw_id>_<ms>")) —
// decrypt it and take the prefix before '_' to get the raw toy ID.
static std::string raw_toy_id(const std::string& list_toyuid) {
    std::string pt = aes_dec(TS_KEY, list_toyuid);
    size_t p = pt.find('_');
    return p == std::string::npos ? pt : pt.substr(0, p);
}

// The device list's bluetoothAddress is b64(AES(BTA_KEY, "<MAC>")) — plaintext MAC.
static std::string raw_mac(const std::string& list_bta) {
    return aes_dec(BTA_KEY, list_bta);
}

// Command responses carry the 32-hex BLE command either plaintext or as
// b64(AES(CMD_KEY, <32-hex>)) — normalize to the 32-hex form.
static std::string decode_command(const std::string& data) {
    static const std::regex hex32("^[0-9a-fA-F]{32}$");
    if (std::regex_match(data, hex32)) return data;
    auto pt = aes_cbc(CMD_KEY, IV, b64_decode(data), false);
    return std::string(pt.begin(), pt.end());
}

// toyUid wire form: b64(AES(TS_KEY, <raw_id>_<now_ms>))
static std::string enc_toyuid(const std::string& raw_id) {
    long long ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    return aes_enc(TS_KEY, raw_id + "_" + std::to_string(ms));
}

// ---------------------------------------------------------------- http

// curl runs in a C TU (src/httpc.c) — from C++ on this host, curl write
// callbacks return 0 / SIGBUS; the same code in plain C works.
extern "C" int http_req(const char* url, const char* body, const char* token,
                       char** out, long* status);

// The app sends the login token as a "token" header (pa.b.a() fills the
// headers map; the URL_PARAM_CHECKOUT_TOKEN name is a red herring).
static std::string curl_req(const std::string& url, const std::string* body,
                            const std::string& token, long& status) {
    char* out = nullptr;
    int rc = http_req(url.c_str(), body ? body->c_str() : nullptr,
                      token.c_str(), &out, &status);
    std::string res(out ? out : "");
    free(out);
    if (rc != 0) throw std::runtime_error("curl error " + std::to_string(rc));
    return res;
}

// POST a compact-JSON object to a closed-backend path; returns decrypted JSON.
static json api_post(const std::string& base, const std::string& path,
                     const json& obj, const std::string& token) {
    std::string body = aes_enc(API_KEY, obj.dump());
    if (std::getenv("QIUI_DEBUG")) {
        // Mirrors the app's logcat "jsonObject:" line for easy diffing.
        std::cerr << "[debug] POST " << base << path << "\n"
                  << "[debug]   token: " << token << "\n"
                  << "[debug]   jsonObject: " << obj.dump() << "\n"
                  << "[debug]   body: " << body << "\n";
    }
    long status = 0;
    std::string raw = curl_req(base + path, &body, token, status);
    if (status != 200) throw std::runtime_error("HTTP " + std::to_string(status) +
                                                " from " + path);
    return json::parse(aes_dec(API_KEY, raw));
}

// GET a closed-backend path (no body) — e.g. the device list, which 405s on POST.
static json api_get(const std::string& base, const std::string& path,
                    const std::string& token) {
    long status = 0;
    std::string raw = curl_req(base + path, nullptr, token, status);
    if (status != 200) throw std::runtime_error("HTTP " + std::to_string(status) +
                                                " from " + path);
    return json::parse(aes_dec(API_KEY, raw));
}

// Reduce the decrypted config blob to a base host. The app ships
// 'CH_HTTP_URL="host/api",...' — take the value (quoted, or up to a
// delimiter if unquoted), strip a trailing /api, and return
// 'https://host/'. The value carries no scheme. Returns "" if the key or
// value is missing.
static std::string host_from_config(const std::string& txt) {
    const std::string key = "CH_HTTP_URL=";
    size_t p = txt.find(key);
    if (p == std::string::npos) return "";
    p += key.size();

    std::string host;
    if (p < txt.size() && txt[p] == '"') {
        // Quoted value: take everything up to the closing quote.
        size_t q = txt.find('"', p + 1);
        if (q == std::string::npos) return "";
        host = txt.substr(p + 1, q - (p + 1));
    } else {
        // Unquoted: take up to the first delimiter.
        static const char* delims = ", \n\r;)\"";
        size_t q = txt.find_first_of(delims, p);
        host = q == std::string::npos ? txt.substr(p) : txt.substr(p, q - p);
    }
    if (host.empty()) return "";

    size_t a = host.find("/api");
    if (a != std::string::npos) host = host.substr(0, a);
    return "https://" + host + "/";
}

static std::string get_base_url() {
    long status = 0;
    std::string raw;
    try {
        raw = curl_req(CONFIG_URL, nullptr, "", status);
    } catch (...) {
        std::cerr << "[!] config fetch failed; using fallback\n";
        return FALLBACK_BASE;
    }
    try {
        std::string host = host_from_config(aes_dec(API_KEY, raw));
        if (!host.empty()) return host;
    } catch (...) {
    }
    return FALLBACK_BASE;
}

// ---------------------------------------------------------------- api flow

struct Device {
    std::string toyUid;  // encrypted b64 as returned by the device list
    std::string toyId;   // raw toy ID (TS-decrypted, prefix before '_')
    std::string mac;     // raw MAC (BTA-decrypted)
    std::string serial;
    int role = 1;
    int typeId = 4;
};

static std::string do_login(const std::string& base) {
    const std::string creds = env_or("QIUI_CREDENTIALS", "credentials.txt");
    const std::string cu  = read_cred(creds, "userName");
    const std::string cp  = read_cred(creds, "passWord");
    const std::string cph = read_cred(creds, "phoneId");
    const std::string cbb = read_cred(creds, "blackBox");
    const std::string env_pass = env_or(ENV_PASSWD, "");
    json body = {
        {"platformType", "2"},
        {"userName", cu.empty() ? env_or(ENV_EMAIL, CAP_EMAIL) : cu},
        {"versionNum", "7.0.58"},
        {"registrationId", ""},
        {"loginType", "3"},
        {"passWord", cp.empty()
                         ? (env_pass.empty() ? CAP_PASSWD_B64
                                              : aes_enc(PWD_KEY, env_pass))
                         : cp},
        {"appLanguage", 2},
        {"phoneId", cph.empty() ? env_or(ENV_PHONEID, CAP_PHONEID) : cph},
        {"blackBox", cbb.empty() ? env_or(ENV_BLACKBOX, CAP_BLACKBOX) : cbb},
        {"deviceType", "2"},
    };
    json j = api_post(base, "api/feign/userInfo/login", body, "");
    if (std::getenv("QIUI_DEBUG"))
        std::cerr << "[debug] login response: " << j.dump() << "\n";
    if (j.value("state", "") != "success" ||
        j["data"].value("token", std::string()).empty())
        throw std::runtime_error("login failed: " + j.dump());
    std::cout << "[+] logged in uid=" << j["data"]["uid"] << "\n";
    return j["data"]["token"].get<std::string>();
}

static Device pick_device(const std::string& base, const std::string& token,
                          const std::string& sel) {
    json j = api_get(base, "api/feign/toyUserBinding/getUserBindingToyDevices",
                     token);
    if (j.value("state", "") != "success")
        throw std::runtime_error("device list failed: " + j.dump());
    for (const auto& d : j["data"]) {
        std::string sn = d.value("serialNumber", "");
        std::string name = d.value("toyName", "");
        if (sn == sel || name.rfind(sel, 0) == 0) {
            std::cout << "[+] device: " << name << " sn=" << sn
                      << " typeId=" << d.value("typeId", 0) << "\n";
            Device dev;
            dev.toyUid = d["toyUid"].get<std::string>();
            dev.toyId = raw_toy_id(dev.toyUid);
            dev.mac = d.contains("bluetoothAddress")
                          ? raw_mac(d["bluetoothAddress"].get<std::string>())
                          : "";
            dev.serial = sn;
            dev.role = d.value("toyRole", 1);
            dev.typeId = d.value("typeId", 4);
            std::cout << "[+] raw toyId=" << dev.toyId << " mac=" << dev.mac
                      << "\n";
            return dev;
        }
    }
    throw std::runtime_error("no device matching '" + sel + "'");
}

// ---------------------------------------------------------------- ble

static simpleble_peripheral_t g_periph = nullptr;
static std::mutex g_reply_mtx;
static std::condition_variable g_reply_cv;
static std::vector<uint8_t> g_reply;
static long g_gen = 0;  // bumped by on_notify; lets write_and_wait ignore stale replies

// All hex output is uppercase; the BLE reply path sends this straight to the
// API, so the case is protocol-relevant — keep it stable.
static std::string to_hex(const uint8_t* d, size_t n) {
    static const char* h = "0123456789ABCDEF";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = h[d[i] >> 4];
        out[i * 2 + 1] = h[d[i] & 15];
    }
    return out;
}

static std::string to_hex(const std::vector<uint8_t>& in) {
    return to_hex(in.data(), in.size());
}

static std::vector<uint8_t> from_hex(const std::string& s) {
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int a = val(s[i]), b = val(s[i + 1]);
        if (a < 0 || b < 0) throw std::runtime_error("bad hex: " + s);
        out.push_back((uint8_t)((a << 4) | b));
    }
    return out;
}

static std::string norm_uuid(std::string u) {
    for (auto& c : u) c = (char)std::tolower((unsigned char)c);
    return u;
}

static void wait_for(bool (*pred)(), int timeout_s, const char* what) {
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline)
            throw std::runtime_error(std::string("timed out waiting for ") + what);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

static void check_err(simpleble_error_t** err, const char* what) {
    if (err && *err) {
        std::string msg = std::string(what) + ": " + simpleble_error_message(*err);
        simpleble_error_release(err);
        throw std::runtime_error(msg);
    }
}

static simpleble_uuid_t make_uuid(const std::string& s) {
    simpleble_uuid_t u;
    std::strncpy(u.value, s.c_str(), SIMPLEBLE_UUID_STR_LEN - 1);
    u.value[SIMPLEBLE_UUID_STR_LEN - 1] = 0;
    return u;
}

static void on_notify(simpleble_peripheral_t, simpleble_uuid_t, simpleble_uuid_t,
                      const uint8_t* data, size_t len, void*) {
    std::lock_guard<std::mutex> lk(g_reply_mtx);
    g_reply.assign(data, data + len);
    ++g_gen;
    g_reply_cv.notify_all();
}

// Concatenated hex of all advertised manufacturer-data payloads.
static std::string mfr_hex(simpleble_peripheral_t p) {
    simpleble_error_t* err = nullptr;
    simpleble_manufacturer_data_list_t mds = nullptr;
    if (!simpleble_peripheral_manufacturer_data(p, &mds, &err)) {
        check_err(&err, "manufacturer data");
        return "";
    }
    std::string s;
    for (size_t k = 0; k < simpleble_manufacturer_data_list_count(mds); k++) {
        simpleble_manufacturer_data_t md = {};
        simpleble_manufacturer_data_list_get(mds, k, &md, &err);
        check_err(&err, "md get");
        s += to_hex(md.data, md.data_length);
        simpleble_manufacturer_data_release(&md);
    }
    simpleble_manufacturer_data_list_release(mds);
    return s;
}

// Match by advertised name AND (if mfr_filter is non-empty) manufacturer
// data — all cellmate boards share the name QIUI104.
static void ble_setup(const std::string& uuid, const std::string& mfr_filter) {
    simpleble_error_t* err = nullptr;

    simpleble_adapter_list_t adapters = nullptr;
    simpleble_adapter_get_adapters(&adapters, &err);
    check_err(&err, "get adapters");
    if (simpleble_adapter_list_count(adapters) == 0)
        throw std::runtime_error("no Bluetooth adapter found");
    simpleble_adapter_t adapter = simpleble_adapter_list_get(adapters, 0, &err);
    check_err(&err, "get adapter");

    // The device advertises in bursts — scan in rounds until it shows up.
    std::string target = norm_uuid(uuid);
    std::string mfr = norm_uuid(mfr_filter);
    g_periph = nullptr;
    for (int round = 1; round <= 3 && !g_periph; round++) {
        simpleble_adapter_scan_start(adapter, &err);
        check_err(&err, "scan start");
        std::this_thread::sleep_for(std::chrono::seconds(5));
        simpleble_adapter_scan_stop(adapter, &err);
        check_err(&err, "scan stop");

        simpleble_peripheral_list_t perips = nullptr;
        simpleble_adapter_scan_get_results(adapter, &perips, &err);
        check_err(&err, "scan results");

    for (size_t i = 0; i < simpleble_peripheral_list_count(perips); i++) {
        simpleble_peripheral_t p = simpleble_peripheral_list_get(perips, i, &err);
        check_err(&err, "peripheral list get");
        char* id = simpleble_peripheral_identifier(p, &err);
        check_err(&err, "peripheral identifier");
        std::string pmfr = mfr_hex(p);
        // pmfr is uppercase hex; the filter was lowercased by norm_uuid.
        bool match = id && norm_uuid(id) == target &&
                     (mfr.empty() || norm_uuid(pmfr).find(mfr) != std::string::npos);
        if (id) std::cout << "[*] scanned " << id << " mfr=" << pmfr
                          << (match ? "  <- match" : "") << "\n";
        if (id) simpleble_free(id);
        if (match) {
            g_periph = p;
            break;
        }
        simpleble_peripheral_release_handle(p);
    }
        simpleble_peripheral_list_release(perips);
        if (!g_periph)
            std::cout << "[*] round " << round << ": not found, retrying\n";
    }  // end rounds
    if (!g_periph)
        throw std::runtime_error("device " + uuid +
                                 (mfr.empty() ? "" : " (mfr " + mfr + ")") +
                                 " not found in scan — device powered on and in "
                                 "range?");

    // The WinRT radio can reject a connect issued right after scan_stop
    // ("method was called at an unexpected time") — retry with backoff.
    for (int attempt = 1; ; attempt++) {
        simpleble_error_t* cerr = nullptr;
        simpleble_peripheral_connect(g_periph, &cerr);
        if (!cerr)
            break;
        std::string msg = simpleble_error_message(cerr);
        simpleble_error_release(&cerr);
        bool already = false;
        simpleble_error_t* e2 = nullptr;
        already = simpleble_peripheral_is_connected(g_periph, &e2);
        simpleble_error_release(&e2);
        if (already)
            break;
        if (attempt >= 4)
            throw std::runtime_error("connect: " + msg);
        std::cout << "[!] connect failed (" << msg << "), retry "
                  << attempt << "/3\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    wait_for([] {
        simpleble_error_t* e = nullptr;
        bool c = simpleble_peripheral_is_connected(g_periph, &e);
        simpleble_error_release(&e);
        return c;
    }, 15, "BLE connection");

    // GATT discovery (required before GATT operations)
    simpleble_service_list_t svcs = nullptr;
    simpleble_peripheral_services(g_periph, &svcs, &err);
    check_err(&err, "GATT discovery");
    for (size_t i = 0; i < simpleble_service_list_count(svcs); i++) {
        simpleble_service_t s = {};
        simpleble_service_list_get(svcs, i, &s, &err);
        if (getenv("QIUI_BLE_DEBUG"))
            std::cout << "[dbg] discovered service: " << s.uuid.value << "\n";
        if (s.uuid.value[0]) simpleble_service_release(&s);
    }
    simpleble_service_list_release(svcs);

    simpleble_peripheral_notify(g_periph, make_uuid(SVC_UUID), make_uuid(NT_UUID),
                                on_notify, nullptr, &err);
    check_err(&err, "subscribe notify");
}

// Dump everything the radio can see for each discovered peripheral:
// name, address, address type, RSSI, raw manufacturer data. No login.
static void scan_dump(int rounds) {
    simpleble_error_t* err = nullptr;
    simpleble_adapter_list_t adapters = nullptr;
    simpleble_adapter_get_adapters(&adapters, &err);
    check_err(&err, "get adapters");
    if (simpleble_adapter_list_count(adapters) == 0)
        throw std::runtime_error("no Bluetooth adapter found");
    simpleble_adapter_t adapter = simpleble_adapter_list_get(adapters, 0, &err);
    check_err(&err, "get adapter");

    // Dedup by address (RSSI varies every round, so it must not be part of
    // the key); keep the strongest sighting and print once at the end.
    std::map<std::string, std::pair<int16_t, std::string>> best;
    for (int round = 1; round <= rounds; round++) {
        simpleble_adapter_scan_start(adapter, &err);
        check_err(&err, "scan start");
        std::this_thread::sleep_for(std::chrono::seconds(5));
        simpleble_adapter_scan_stop(adapter, &err);
        check_err(&err, "scan stop");

        simpleble_peripheral_list_t perips = nullptr;
        simpleble_adapter_scan_get_results(adapter, &perips, &err);
        check_err(&err, "scan results");
        for (size_t i = 0; i < simpleble_peripheral_list_count(perips); i++) {
            simpleble_peripheral_t p =
                simpleble_peripheral_list_get(perips, i, &err);
            check_err(&err, "peripheral list get");
            char* id = simpleble_peripheral_identifier(p, &err);
            check_err(&err, "identifier");
            char* addr = simpleble_peripheral_address(p, &err);
            check_err(&err, "address");
            int16_t rssi = simpleble_peripheral_rssi(p, &err);
            simpleble_address_type_t at =
                simpleble_peripheral_address_type(p, &err);

            std::string line = std::string("name=") + (id ? id : "?") +
                               " addr=" + (addr ? addr : "?") +
                               " type=" + std::to_string((int)at) +
                               " rssi=" + std::to_string(rssi);

            simpleble_manufacturer_data_list_t mds = nullptr;
            simpleble_peripheral_manufacturer_data(p, &mds, &err);
            check_err(&err, "manufacturer data");
            std::string mfr;
            for (size_t k = 0; k < simpleble_manufacturer_data_list_count(mds); k++) {
                simpleble_manufacturer_data_t md = {};
                simpleble_manufacturer_data_list_get(mds, k, &md, &err);
                check_err(&err, "md get");
                char idbuf[8];
                snprintf(idbuf, sizeof idbuf, "%04x", md.manufacturer_id);
                mfr += " mfr=" + std::string(idbuf) + ":" +
                       to_hex(md.data, md.data_length);
                simpleble_manufacturer_data_release(&md);
            }
            simpleble_manufacturer_data_list_release(mds);

            line += mfr;
            std::string key = addr ? addr : (id ? id : "?");
            auto it = best.find(key);
            if (it == best.end() || rssi > it->second.first)
                best[key] = {rssi, line};

            if (id) simpleble_free(id);
            if (addr) simpleble_free(addr);
            simpleble_peripheral_release_handle(p);
        }
        simpleble_peripheral_list_release(perips);
    }
    for (auto& kv : best)
        std::cout << kv.second.second << "\n";
}

// Write 16 bytes (32-hex) to ae3b and wait for the 16-byte reply on ae3c.
static std::string write_and_wait(const std::string& hex, int timeout_s = 15) {
    {
        // Reset under the lock BEFORE issuing the write: a reply can arrive at
        // any moment, and clearing after the generation snapshot would lose it.
        std::lock_guard<std::mutex> lk(g_reply_mtx);
        g_reply.clear();
        g_gen = 0;
    }
    auto bytes = from_hex(hex);
    simpleble_error_t* err = nullptr;
    simpleble_peripheral_write_command(g_periph, make_uuid(SVC_UUID),
                                        make_uuid(WR_UUID), bytes.data(),
                                        bytes.size(), &err);
    check_err(&err, "BLE write");
    long before = 0;
    std::unique_lock<std::mutex> lk(g_reply_mtx);
    if (!g_reply_cv.wait_for(lk, std::chrono::seconds(timeout_s),
                              [&] { return g_gen > before && !g_reply.empty(); }))
        throw std::runtime_error("no BLE reply within " +
                                  std::to_string(timeout_s) + " s");
    return to_hex(g_reply);
}

static void ble_teardown() {
    if (!g_periph) return;
    try {
        simpleble_error_t* err = nullptr;
        simpleble_peripheral_disconnect(g_periph, &err);
        simpleble_error_release(&err);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    } catch (...) {
    }
}

// ---------------------------------------------------------------- commands

static json post_decry(const std::string& base, const std::string& token,
                       const Device& dev, const std::string& reply_hex);

// Lock timer (timed lock). While an active timing lock exists the server refuses
// unlockToy until it expires or is cancelled. All server-side (toyUid only, no BLE):
//   set <minutes>  saveManualTimingRecord {timingTime=<minutes>} -> data.uid,
//                then toyUseTimingRecord {timingUid, toyUid, type:"1"}
//   list         getAllToyUnlockTimingRecords {toyUid} -> outstanding records
//   cancel <id> [type]  cancelTimingLock {toyUid, timingId, timingType}
static void run_lock_timer(const std::string& base, const std::string& token,
                           const Device& dev, const std::string& sub,
                           long val, const std::string& arg) {
    if (sub == "list") {
        json j = api_post(base,
                          "api/feign/toyElectricTimingRecord/getAllToyUnlockTimingRecords",
                          {{"toyUid", enc_toyuid(dev.toyId)}}, token);
        if (j.value("state", "") != "success")
            throw std::runtime_error("getAllToyUnlockTimingRecords failed: " + j.dump());
        json data = j.contains("data") ? j["data"] : json::array();
        if (!data.is_array() || data.empty()) {
            std::cout << "[+] no outstanding lock timers\n";
            return;
        }
        std::cout << "[+] " << data.size() << " outstanding lock timer(s):\n";
        for (const auto& r : data)
            std::cout << "    " << r.dump() << "\n";
        return;
    }
    if (sub == "status") {
        json d = api_post(base, "api/feign/toyUserBinding/getToyBindingInfoDetail",
                          {{"toyUid", enc_toyuid(dev.toyId)}}, token);
        if (d.value("state", "") != "success")
            throw std::runtime_error("getToyBindingInfoDetail failed: " + d.dump());
        json bd = d.contains("data") && d["data"].is_object() ? d["data"] : json::object();
        auto strfield = [](const json& o, const char* k) -> std::string {
            if (!o.contains(k)) return "";
            const json& v = o[k];
            return v.is_string() ? v.get<std::string>() : v.dump();
        };
        // timingTime = "d-h-m-s", counting down in real time; timingTimeMillis
        // is the same countdown in SECONDS despite its name.
        std::string tid2 = strfield(bd, "timingId");
        std::string ttime = strfield(bd, "timingTime");
        if (tid2.empty() || ttime.empty() || ttime == "0") {
            std::cout << "[+] no active lock timer\n";
        } else {
            std::cout << "[+] active lock timer id=" << tid2
                      << " type=" << strfield(bd, "timingType")
                      << " remaining=" << ttime << " (d-h-m-s)\n";
        }
        return;
    }
    if (sub == "set") {
        long minutes = val;  // app picker: d*1440 + h*60 + m
        if (minutes < 1) throw std::runtime_error("duration must be >= 1 min");
        json j = api_post(base, "api/feign/toyManualTimingRecord/saveManualTimingRecord",
                          {{"timingTime", std::to_string(minutes)},
                           {"toyUid", enc_toyuid(dev.toyId)}}, token);
        if (j.value("state", "") != "success")
            throw std::runtime_error("saveManualTimingRecord failed: " + j.dump());
        json data = j["data"];
        long uid;
        if (data.is_array() && !data.empty() && data[0].contains("uid"))
            uid = data[0]["uid"].get<long>();
        else if (data.is_object() && data.contains("uid"))
            uid = data["uid"].get<long>();
        else
            throw std::runtime_error("saveManualTimingRecord: no record uid in response: " + j.dump());
        std::cout << "[+] created timing record uid=" << uid << "\n";
        json u = api_post(base, "api/feign/toyUserBinding/toyUseTimingRecord",
                          {{"timingUid", std::to_string(uid)},
                           {"toyUid", enc_toyuid(dev.toyId)},
                           {"type", "1"}}, token);
        if (u.value("state", "") != "success")
            throw std::runtime_error("toyUseTimingRecord failed: " + u.dump());
        std::cout << "[+] lock timer applied (" << minutes << " min)\n";
        return;
    }
    if (sub == "cancel") {
        std::string tid, ttype;
        if (val >= 1) {
            tid = std::to_string(val);
            ttype = arg.empty() ? "1" : arg;
        } else {
            // No explicit id: the app shows a single active timer whose
            // id/type come from getToyBindingInfoDetail.data.
            json d = api_post(base, "api/feign/toyUserBinding/getToyBindingInfoDetail",
                              {{"toyUid", enc_toyuid(dev.toyId)}}, token);
            if (d.value("state", "") != "success")
                throw std::runtime_error("getToyBindingInfoDetail failed: " + d.dump());
            json bd = d.contains("data") && d["data"].is_object() ? d["data"] : json::object();
            auto strfield = [](const json& o, const char* k) -> std::string {
                if (!o.contains(k)) return "";
                const json& v = o[k];
                return v.is_string() ? v.get<std::string>() : v.dump();
            };
            tid = strfield(bd, "timingId");
            ttype = strfield(bd, "timingType");
            if (tid.empty()) { std::cout << "[+] no active lock timer to cancel\n"; return; }
            if (ttype.empty()) ttype = "1";
            std::cout << "[*] active timer id=" << tid << " type=" << ttype << "\n";
        }
        json c = api_post(base, "api/feign/toyCancelTimingRecord/cancelTimingLock",
                          {{"toyUid", enc_toyuid(dev.toyId)},
                           {"timingId", tid},
                           {"timingType", ttype}}, token);
        if (c.value("state", "") != "success")
            throw std::runtime_error("cancelTimingLock failed: " + c.dump());
        std::cout << "[+] cancelled lock timer id=" << tid << "\n";
        return;
    }
    throw std::runtime_error("unknown lock-timer subcommand '" + sub +
                             "' (use list | set <secs> | cancel <timingId> [type])");
}

// Immediate shock.
// Unlike the
// timed flow there is NO save/sync/delete and NO beginElectricTime: a POST to
// getToyShockImmediately returns a command we write straight to ae3b; we re-send
// it roughly once per second to sustain the effect for `secs` seconds. Body is
// {shockModel, shockVolt, toyUid} (note shockModel, not electricMode). The app
// only reaches this after the connect/token priming, so mirror that here with a
// getToyToken round-trip first.
static void run_shock_now(const std::string& base, const std::string& token,
                          const Device& dev, int secs, int volt, int mode) {
    if (secs < 1) throw std::runtime_error("shock duration must be >= 1 s");
    if (volt < 1 || volt > 4) throw std::runtime_error("shockVolt must be 1-4");
    if (mode < 1 || mode > 3)
        throw std::runtime_error("shockModel must be 1-3 (1 vibrate, 2 tremble, 3 sting)");

    // Prime server state with a token write (the app has already run this on
    // connect; the timed-mint notes show the server only mints for toys that
    // just authenticated). Writing getToyToken's command is a benign battery
    // readback ({battery, commandCode:"13"}), not an unlock/lock.
    {
        json j = api_post(base, "api/feign/toyCellmateBluetooth/getToyToken",
                          {{"toyUid", enc_toyuid(dev.toyId)}}, token);
        if (j.value("state", "") != "success" || !j["data"].is_string())
            throw std::runtime_error("getToyToken failed: " + j.dump());
        std::string hex = decode_command(j["data"].get<std::string>());
        std::cout << "[*] token -> " << hex << "\n";
        std::string reply = write_and_wait(hex);
        post_decry(base, token, dev, reply);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Mint the immediate command ONCE, then re-send the same 32-hex to the board
    // roughly once per second for `secs` seconds (no re-minting).
    json j = api_post(base, "api/feign/toyCellmateBluetooth/getToyShockImmediately",
                      {{"shockModel", std::to_string(mode)},
                       {"shockVolt", std::to_string(volt)},
                       {"toyUid", enc_toyuid(dev.toyId)}}, token);
    if (j.value("state", "") != "success" || !j["data"].is_string())
        throw std::runtime_error("getToyShockImmediately failed: " + j.dump());
    std::string hex = decode_command(j["data"].get<std::string>());
    std::cout << "[+] immediate shock command -> " << hex << "\n";

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(secs);
    for (int n = 0;;) {
        std::string reply = write_and_wait(hex);
        post_decry(base, token, dev, reply);
        if (n > 0) std::cout << "[*] resend " << n << " -> " << reply << "\n";
        if (std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++n;
    }
}

// Shock: save a timed-shock record,
// sync it to get the minted lockCommand(s), write them to the device,
// decrypt each reply. Ranges from the app UI: 1-20 s, volt 1-4, mode 1-3.
static void run_shock(const std::string& base, const std::string& token,
                      const Device& dev, int secs, int volt, int mode) {
    if (secs < 1 || secs > 20)
        throw std::runtime_error("shock duration must be 1-20 s");
    if (volt < 1 || volt > 4) throw std::runtime_error("shockVolt must be 1-4");
    if (mode < 1 || mode > 3)
        throw std::runtime_error("electricMode must be 1-3 (1 vibrate, 2 tremble, 3 sting)");
    // beginElectricTime is a RELATIVE offset from now, in seconds
    // (server sets begin = now + bet*1000). The app rejects 0 (00:00:00),
    // so the minimum is 1 minute. Start ~1 min out so the command is minted
    // shortly after we begin polling.
    const int bet = 60;
    json body = {
        {"electricShockTime", std::to_string(secs)},
        {"electricMode", std::to_string(mode)},
        {"shockVolt", std::to_string(volt)},
        {"beginElectricTime", std::to_string(bet)},
        {"toyUid", enc_toyuid(dev.toyId)},
    };
    json j = api_post(base, "api/feign/toyElectricTimingRecord/saveElectricTimingRecord",
                      body, token);
    if (j.value("state", "") != "success")
        throw std::runtime_error("saveElectricTimingRecord failed: " + j.dump());
    std::cout << "[+] shock saved (" << secs << "s volt=" << volt << " mode=" << mode
              << "), starts in " << bet << "s\n";

    // The app always syncs right after a successful token write — the server
    // appears to only mint shock commands for toys that just authenticated.
    {
        json j = api_post(base, "api/feign/toyCellmateBluetooth/getToyToken",
                          {{"toyUid", enc_toyuid(dev.toyId)}}, token);
        if (j.value("state", "") != "success" || !j["data"].is_string())
            throw std::runtime_error("getToyToken failed: " + j.dump());
        std::string hex = decode_command(j["data"].get<std::string>());
        std::cout << "[*] token -> " << hex << "\n";
        std::string reply = write_and_wait(hex);
        post_decry(base, token, dev, reply);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // The server mints a real (non-zero) lockCommand once the start time
    // arrives; before that it returns an all-zero placeholder. Poll sync
    // until a real command shows up.
    auto non_zero = [](const std::string& h) {
        for (char c : h) if (c != '0') return true;
        return false;
    };
    int n = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(bet + 120);
    for (;;) {
        json s = api_post(
            base, "api/feign/toyElectricTimingRecord/synchronizeElectricTimingRecord",
            {{"toyUid", enc_toyuid(dev.toyId)}}, token);
        if (s.value("state", "") != "success")
            throw std::runtime_error("synchronizeElectricTimingRecord failed: " + s.dump());
        if (std::getenv("QIUI_DEBUG")) {
            std::cerr << "[debug] sync: " << s.dump() << "\n";
        }
        bool got = false;
        for (const auto& r : s["data"]) {
            std::string lc = r.value("lockCommand", std::string());
            if (lc.empty() || r.value("electricShockTime", 0) == 0) continue;
            std::string hex = decode_command(lc);
            if (!non_zero(hex)) continue;  // not due yet
            std::cout << "[*] shock command " << ++n << " -> " << hex << "\n";
            std::string reply = write_and_wait(hex);
            post_decry(base, token, dev, reply);
            // Remove the record so it can't resurface in a later sync.
            if (r.contains("uid")) {
                try {
                    api_post(base,
                             "api/feign/toyElectricTimingRecord/deleteElectricTimingRecord",
                             {{"uid", r["uid"].dump()},
                              {"toyUid", enc_toyuid(dev.toyId)}},
                             token);
                } catch (...) {
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            got = true;
        }
        if (got) break;
        if (std::chrono::steady_clock::now() > deadline)
            throw std::runtime_error("shock command never minted (start time passed?)");
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

static json post_decry(const std::string& base, const std::string& token,
                       const Device& dev, const std::string& reply_hex) {
    // The app sends the reply hex AES-encrypted with the BLUETOOTH_COMMAND
    // key (EncryptUtil.g(BLUETOOTH_COMMAND, str)), not raw.
    json body = {{"lockCommand", aes_enc(CMD_KEY, reply_hex)},
                 {"toyUid", enc_toyuid(dev.toyId)}};
    json j = api_post(base, "api/feign/toyCellmateBluetooth/decryBluetoothCommand",
                      body, token);
    if (j.value("state", "") == "success" && j.contains("data"))
        std::cout << "    reply " << reply_hex << " -> " << j["data"].dump() << "\n";
    else
        std::cout << "    reply " << reply_hex << " -> (raw) " << j.dump() << "\n";
    return j;
}

// Prime the server's toy state (the app does this right after BLE connect,
// before minting a token): raw MAC + TS-enc toyUid.
static void prime_binding(const std::string& base, const std::string& token,
                          const Device& dev) {
    json body = {{"bluetoothAddress", dev.mac},
                 {"toyUid", enc_toyuid(dev.toyId)}};
    try {
        json j = api_post(base, "api/feign/toyUserBinding/getToyBindingInfoDetail",
                          body, token);
        std::cout << "[*] getToyBindingInfoDetail: " << j.value("state", "?")
                  << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[!] getToyBindingInfoDetail: " << e.what() << "\n";
    }
}

// Fetch a 32-hex command from the server, write it to the device, wait for
// the 16-byte reply, decrypt it server-side, print the result.
// The app retries token minting a few times; do the same.
static void run_command(const std::string& base, const std::string& token,
                        const Device& dev, const std::string& path,
                        const json& body, int settle_ms = 1000) {
    json j;
    for (int attempt = 1; ; attempt++) {
        j = api_post(base, path, body, token);
        if (j.value("state", "") == "success" && j["data"].is_string()) break;
        if (attempt >= 3)
            throw std::runtime_error(path + " failed: " + j.dump());
        std::cerr << "[!] " << path << " attempt " << attempt << " failed: "
                  << j.dump() << " — retrying\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::string hex = decode_command(j["data"].get<std::string>());
    std::cout << "[*] " << path << " -> " << hex << "\n";
    std::string reply = write_and_wait(hex);
    post_decry(base, token, dev, reply);
    std::this_thread::sleep_for(std::chrono::milliseconds(settle_ms));
}

// ---------------------------------------------------------------- main

int main(int argc, char** argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (argc < 3) {
        std::cerr <<
            "Usage: cellmate2 <serial|name-prefix> <command> [args]\n"
            "  commands: devices | token | unlock [role] | lock | clear-shock |\n"
            "            clear-timed-unlock | full (token+unlock+lock) |\n"
            "            shock [secs=10] [volt=1] [mode=1..3] (timed) |\n"
            "            shock-now [secs=1] [volt=1] [mode=1..3] (immediate) |\n"
            "            lock-timer list | status | set <minutes> | cancel [id] [type]\n"
            "  offline:   enc-pass '<plain password>' | scan-dump [rounds=2]\n"
            "            (command-first form, no login needed)\n"
            "Credentials: ./credentials.txt (see README.md); env overrides:\n"
            "Env: " << ENV_EMAIL << " " << ENV_PASSWD << " " << ENV_TOKEN
            << " " << ENV_BLACKBOX << " " << ENV_PHONEID << " " << ENV_UUID
            << " " << ENV_MFR << " QIUI_CREDENTIALS\n";
        return 1;
    }
    std::string sel = argv[1];
    std::string cmd = argv[2];

    // Offline helper: encrypt a plain password the way the app does
    // (AES-256-CBC, PWD_KEY, fixed IV) and print the base64 form.
    //   cellmate2 - enc-pass 'myPassword'
    if (cmd == "enc-pass") {
        if (argc < 4) {
            std::cerr << "Usage: cellmate2 - enc-pass '<plain password>'\n";
            return 1;
        }
        std::cout << aes_enc(PWD_KEY, argv[3]) << "\n";
        return 0;
    }

    if (cmd == "scan-dump") {
        int rounds = 2;
        if (argc > 3) {
            try {
                rounds = std::stoi(argv[3]);
            } catch (const std::exception&) {
                std::cerr << "[!] bad round count '" << argv[3]
                          << "', using 2\n";
            }
        }
        scan_dump(rounds);
        return 0;
    }

    bool ok = false;
    try {
        std::string base = get_base_url();
        std::cout << "[*] base URL: " << base << "\n";
        // Prefer a captured session token (works from any IP; blackBox is
        // bound to the phone's risk-control profile and cannot be replayed).
        const std::string creds0 = env_or("QIUI_CREDENTIALS", "credentials.txt");
        const std::string token0 = env_or(ENV_TOKEN, read_cred(creds0, "token"));
        std::string token;
        if (token0.empty())
            token = do_login(base);
        else {
            token = token0;
            std::cout << "[+] using captured session token\n";
        }

        if (cmd == "devices") {
            json j = api_get(base, "api/feign/toyUserBinding/getUserBindingToyDevices",
                             token);
            for (const auto& d : j["data"])
                std::cout << "    " << d.value("toyName", "?")
                          << "  sn=" << d.value("serialNumber", "?")
                          << "  typeId=" << d.value("typeId", 0)
                          << "  role=" << d.value("toyRole", 0) << "\n";
            return 0;
        }

        Device dev = pick_device(base, token, sel);
        if (dev.typeId != 4)
            std::cerr << "[!] warning: deviceId typeId=" << dev.typeId
                      << " (expected 4 for cellmate II)\n";

        // Lock timer: pure server-side (toyUid only), no BLE needed.
        if (cmd == "lock-timer") {
            run_lock_timer(base, token, dev,
                           argc > 3 ? argv[3] : std::string("list"),
                           argc > 4 ? std::stol(argv[4]) : 0L,
                           argc > 5 ? argv[5] : std::string());
            ok = true;
        } else {
        // Match by advertised name + manufacturer data: the CoreBluetooth
        // UUID rotates with the device's private address, the name is shared
        // by all cellmate boards, the mfr payload is stable per device.
        std::string uuid = env_or(ENV_UUID, "QIUI104");
        std::string mfr = env_or(ENV_MFR, CAP_MFR);
        ble_setup(uuid, mfr);
        std::cout << "[*] BLE connected, notify on ae3c enabled\n";

        prime_binding(base, token, dev);

        if (cmd == "token") {
            run_command(base, token, dev,
                        "api/feign/toyCellmateBluetooth/getToyToken",
                        {{"toyUid", enc_toyuid(dev.toyId)}});
        } else if (cmd == "unlock") {
            int role = argc > 3 ? std::stoi(argv[3]) : dev.role;
            run_command(base, token, dev, "api/feign/toyBluetooth/unlockToy",
                        {{"unLockType", "0"}, {"type", role},
                         {"toyUid", enc_toyuid(dev.toyId)}});
        } else if (cmd == "lock") {
            run_command(base, token, dev,
                        "api/feign/toyCellmateBluetooth/toyCloseLock",
                        {{"toyUid", enc_toyuid(dev.toyId)}});
        } else if (cmd == "clear-shock") {
            run_command(base, token, dev,
                        "api/feign/toyCellmateBluetooth/clearToyTimingElectricShock",
                        {{"toyUid", enc_toyuid(dev.toyId)}});
        } else if (cmd == "clear-timed-unlock") {
            run_command(base, token, dev,
                        "api/feign/toyCellmateBluetooth/clearToyUnlockTimingTime",
                        {{"toyUid", enc_toyuid(dev.toyId)}});
        } else if (cmd == "shock") {
            int secs = argc > 3 ? std::stoi(argv[3]) : 10;
            int volt = argc > 4 ? std::stoi(argv[4]) : 1;
            int mode = argc > 5 ? std::stoi(argv[5]) : 1;
            run_shock(base, token, dev, secs, volt, mode);
        } else if (cmd == "shock-now") {
            int secs = argc > 3 ? std::stoi(argv[3]) : 1;
            int volt = argc > 4 ? std::stoi(argv[4]) : 1;
            int mode = argc > 5 ? std::stoi(argv[5]) : 1;
            run_shock_now(base, token, dev, secs, volt, mode);
        } else if (cmd == "full") {
            run_command(base, token, dev,
                        "api/feign/toyCellmateBluetooth/getToyToken",
                        {{"toyUid", enc_toyuid(dev.toyId)}}, 2000);
            int role = argc > 3 ? std::stoi(argv[3]) : dev.role;
            run_command(base, token, dev, "api/feign/toyBluetooth/unlockToy",
                        {{"unLockType", "0"}, {"type", role},
                         {"toyUid", enc_toyuid(dev.toyId)}}, 2000);
            run_command(base, token, dev,
                        "api/feign/toyCellmateBluetooth/toyCloseLock",
                        {{"toyUid", enc_toyuid(dev.toyId)}});
        } else {
            throw std::runtime_error("unknown command " + cmd);
        }
        }
        ok = true;
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << "\n";
    }

    ble_teardown();
    return ok ? 0 : 1;
}
