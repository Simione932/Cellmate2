# Cellmate2

CLI controllers for the QIUI **cellmate II**. There are two implementations
with the same command surface — use whichever you prefer:

- **`cellmate2/`** — C++ (CMake; curl for HTTP, SimpleCBLE for BLE)
- **`cellmate2cs/`** — C# / .NET 10 (System.Net.Http + System.Security.Cryptography +
  SimpleSharpBLE, no curl needed)

This file is about how to *run* them.

## Credentials

The server rejects script-forged logins that lack a real Netease HTProtect
`blackBox`, so the easiest way in is to drive the real app on a dev phone and
capture what it sends. Both apps read `Cellmate2/credentials.txt` (key=value
lines: `userName`, `passWord` — base64 AES-encrypted, `phoneId`, `blackBox`),
which is written by:

```bash
cd Cellmate2
python3 capture_login.py <email> <password> [out-log-file] [creds-file]
```

The script clears and relaunches the app over adb, fills in the login form,
and grabs the exact login payload from logcat. You'll need `adb` installed and
USB debugging enabled on the phone.

Two things to keep in mind:

- **Single active session** — any new login (app or these tools) invalidates
  previous tokens. Always run fresh; don't reuse old tokens.
- **`blackBox` is single-use / session-scoped** — if logins start failing with
  `US_100065`, just re-run `capture_login.py`.

Prefer env vars? They override `credentials.txt` (embedded constants are the
last resort): `QIUI_EMAIL`, `QIUI_PASSWORD` (plain), `QIUI_BLACKBOX`,
`QIUI_PHONEID`. Path override: `QIUI_CREDENTIALS`. And `QIUI_DEBUG=1` dumps
per-call URL/token/JSON/body, which is handy when something looks off.

## Building

```bash
# C++
cd Cellmate2/cellmate2
cmake -B build && cmake --build build     # binary: build/cellmate2
# (first build also fetches/builds curl as a dependency)

# C#
cd Cellmate2/cellmate2cs
dotnet build                              # run: dotnet bin/Debug/net10.0/cellmate2cs.dll
```

Run both from the `Cellmate2/` directory so they can find `credentials.txt`.

## Commands

```
cellmate2  <serial|name-prefix> <command> [args]
cellmate2cs <serial|name-prefix> <command> [args]
```

Pick the device by serial number (e.g. `QIUIYZBT00000000`) or name prefix
(`cellmate`). For BLE commands we also match on the stable manufacturer-data
payload, since every board advertises itself as `QIUI104`.

| Command | What it does |
|---|---|
| `devices` | List all bound devices (serial, typeId, role). API only. |
| `token` | BLE connect + `getToyToken` round-trip (battery readback). |
| `unlock [role]` | Unlock the board. `role`: `1`=wearer (the person the board is bound to / worn by), `2`=controller (operates it via the app). Defaults to the device's `toyRole`. |
| `lock` | Lock the board. |
| `full` | `token` → `unlock` → `lock` in one run. |
| `shock [secs=10] [volt=1] [mode=1..3]` | Timed electric shock: server record → token sync → write to board → delete record. |
| `shock-now [secs=1] [volt=1] [mode=1..3]` | Immediate one-shot shock; re-sends the same command ~1/s for `secs`. |
| `clear-shock` | Clear pending timed-shock state on the board. |
| `clear-timed-unlock` | Clear the timed-unlock (lock timer) state on the board. |
| `lock-timer …` | Timed lock — see below. API only, no BLE. |

Shock modes: `1`=Vibrate, `2`=Tremble, `3`=Sting; `volt` is 1–4.

Offline helpers (command-first form — no login or credentials needed):

| Command | What it does |
|---|---|
| `enc-pass '<plain password>'` | Print the app's wire encoding of a password (AES-256-CBC, PWD key, fixed IV, base64). |
| `scan-dump [rounds=2]` | BLE scan dump: advertised name + manufacturer-data payload for every cellmate board in range. Use it to capture a new board's mfr filter (`QIUI_BLE_MFR`). |

### lock-timer

A **timed lock**: while a timer is active, the server refuses `unlockToy`
until it expires or is cancelled. Durations are given in **minutes**.

| Subcommand | What it does |
|---|---|
| `lock-timer list` | Outstanding records (`getAllToyUnlockTimingRecords`). Manual vouchers have no `uid`. |
| `lock-timer status` | The single displayed active timer: id, type, `d-h-m-s` countdown. |
| `lock-timer set <minutes>` | Create a manual voucher and activate it — its duration is added to the active timer. Server caps outstanding vouchers at 2 (`toy_100017`). |
| `lock-timer cancel [id] [type]` | Clear the displayed accumulated timer (id/type auto-resolved from `getToyBindingInfoDetail` when omitted). Does **not** delete stored vouchers — they can only be consumed by activating them. |

⚠ **The server penalizes repeated cancels** — cancelling the displayed timer
too often locks you out of setting new timers for a while.

## BLE environment

| Var | Default | Meaning |
|---|---|---|
| `QIUI_BLE_ID` | `QIUI104` | Advertised name filter (shared by all boards — not unique). |
| `QIUI_BLE_MFR` | main board's payload | Stable per-board manufacturer-data hex filter; the real discriminator. |

## Examples

```bash
cd ~/Cellmate2

# who's bound?
./cellmate2/build/cellmate2 - devices

# full lock/unlock round-trip
./cellmate2/build/cellmate2 QIUIYZBT00000000 full

# one-second immediate sting, voltage 2 (C#)
dotnet cellmate2cs/bin/Debug/net10.0/cellmate2cs.dll QIUIITYQ0000000 shock-now 1 2 3

# lock timers
./cellmate2/build/cellmate2 QIUIITYQ00000000 lock-timer set 5
./cellmate2/build/cellmate2 QIUIITYQ00000000 lock-timer status
./cellmate2/build/cellmate2 QIUIITYQ00000000 lock-timer cancel
```
