# cellmate2

Standalone controller for QIUI "cellmate II" smart locks (ble lock board,
e.g. name `QIUI104`). Talks to the lock over Bluetooth LE and uses the qiui
cloud API for authentication and reply decryption — no phone app needed.

## Usage

```
cellmate2 <serial|name-prefix> <command> [args]
  commands: devices | token | unlock [role] | lock | clear-shock |
            clear-timed-unlock | full (token+unlock+lock) |
            shock [secs=10] [volt=1] [mode=1..3] (timed) |
            shock-now [secs=1] [volt=1] [mode=1..3] (immediate) |
            lock-timer list | status | set <minutes> | cancel [id] [type]
  offline:   enc-pass '<plain password>' | scan-dump [rounds=2]
```

Offline commands take `-` as the first argument, e.g.:

```
cellmate2 - scan-dump 3        # dump every BLE device in range (no login)
cellmate2 - enc-pass 'mypass'  # AES-encrypt a password the way the app does
```

## Credentials

A `key=value` file written by the companion `capture_login.py`, defaulting
to `./credentials.txt` next to the working directory:

```
userName=<your qiui account email>
passWord=<AES-encrypted password blob from the app>
phoneId=<phoneId captured from the app>
blackBox=<risk-control token captured from the app>
token=<session token, after successful capture>
```

**The `token` line is what cellmate2 actually uses**: if present it skips
the login API entirely and calls the cloud with the app's session token.
That works from any machine/IP. Without it (or once it expires) cellmate2
falls back to replaying the login, but the `blackBox` is a risk-control
token bound to the phone's device profile — server rejects PC-side login
replays (`US_100015`) — so in practice: re-run `capture_login.py` when the
token stops working.

`capture_login.py` drives the qiui app over adb (UIA taps, logcat capture)
and needs a phone with USB debugging:

```
QIUI_ADB=E:/path/to/adb.exe python capture_login.py <email> <password>
# writes ./credentials.txt next to the script/cwd
```

The file location can be overridden with `QIUI_CREDENTIALS`. Individual
fields can be overridden per run with env vars:

| Env var         | Purpose                                              |
|-----------------|------------------------------------------------------|
| `QIUI_TOKEN`    | session token (replaces `token`, skips login)        |
| `QIUI_EMAIL`    | account email (replaces `userName`)                  |
| `QIUI_PASSWORD` | plain password (replaces `passWord`)                 |
| `QIUI_BLACKBOX` | replaces `blackBox`                                  |
| `QIUI_PHONEID`  | replaces `phoneId`                                   |
| `QIUI_BLE_ID`   | advertised device name to match (default `QIUI104`)  |
| `QIUI_BLE_MFR`  | manufacturer-data hex filter to disambiguate locks   |
| `QIUI_CREDENTIALS` | path to the credentials file                     |
| `QIUI_CURL_DEBUG` | set to anything for verbose HTTP tracing          |

When multiple boards advertise the same name, capture a distinguishing
manufacturer-data fragment with `cellmate2 - scan-dump` and put it in
`QIUI_BLE_MFR`.

## Building

### macOS

Requires CMake and an SSL library (OpenSSL/LibreSSL/BoringSSL); curl is
fetched automatically.

```
cmake -S cellmate2 -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j8   # -> build/cellmate2
```

SimpleBLE needs a Bluetooth adapter visible to CoreBluetooth.

### Windows

Use `buildwin.cmd` from the repository root (expects the MinGW-20 toolchain
at `E:\MinGW-20` and CMake on disk):

```
buildwin.cmd              # -> build-win\cellmate2.exe
```

curl is built from a release tarball against the LibreSSL headers and static
`libssl.a`/`libcrypto.a` shipped in
`third-party/curl-win/curl-8.23.0_8-win64-mingw/` (same libraries the app's
AES uses). TLS certificate verification uses `third-party/cacert.pem`
(Mozilla bundle, refresh from https://curl.se/ca now and then); the path is
baked in at build time, so rebuild after moving the tree.

## Notes

- Protocol details were reverse-engineered from `qiui.apk`; fixed keys and IV
  live at the top of `src/main.cpp`.
- `write_and_wait` writes 16 bytes to characteristic `ae3b` and expects a
  reply on `ae3c`; replies are decrypted server-side via the
  `decryBluetoothCommand` API.
