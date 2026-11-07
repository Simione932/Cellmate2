#!/usr/bin/env python3
"""Automated Qiui app login capture via adb.

Drives the login UI (privacy dialog -> email / password / checkbox / CONFIRM)
and captures the app's real login payload from logcat
(tag 123, line "登录发送的数据: {...}"; falls back to the decrypted
"基类返回的数据：" response lines when the request marker is absent).

Usage:
  python3 capture_login.py <userid> <password> [out-log-file] [creds-file]

Writes the captured login credentials (userName, passWord, phoneId, blackBox)
to creds-file (default ./credentials.txt), which the C# / C++ apps read.
"""
import os
import re
import subprocess
import sys
import time

PKG = "cellmate.qiui.com"
ADB = os.environ.get("QIUI_ADB", "adb")


def adb_shell(cmd, timeout=90):
    return subprocess.run([ADB, "shell", cmd], capture_output=True,
                          text=True, timeout=timeout)


def dump_ui():
    adb_shell("uiautomator dump /sdcard/ui.xml")
    return adb_shell("cat /sdcard/ui.xml").stdout


def find_center(res_id):
    """Center (x, y) of the first node with resource-id PKG:id/<res_id>."""
    xml = dump_ui()
    pat = (r'resource-id="%s:id/%s"[^>]*bounds="\[(\d+),(\d+)\]\['
           r'(\d+),(\d+)\]"' % (re.escape(PKG), res_id))
    m = re.search(pat, xml)
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


def wait_for(res_id, tries=30, delay=2.0):
    for _ in range(tries):
        c = find_center(res_id)
        if c:
            return c
        time.sleep(delay)
    return None


def tap(x, y):
    adb_shell("input tap %d %d" % (x, y))


def shot(path):
    r = subprocess.run([ADB, "exec-out", "screencap", "-p"],
                       capture_output=True)
    with open(path, "wb") as f:
        f.write(r.stdout)


def extract_json_fields(s):
    """Pull credential-looking fields out of a (decrypted) JSON response line."""
    d = {}
    for k in ("userName", "passWord", "phoneId", "blackBox", "token"):
        m = re.search(r'"%s"\s*:\s*"((?:[^"\\]|\\.)*)"' % k, s)
        if m:
            d[k] = m.group(1)
    return d


def _strip_logcat_prefix(line):
    m = re.match(r'^\d\d-\d\d [\d:.]+ +[A-Z]/\S+\s*\(\d+\): ?(.*)$', line.rstrip())
    return m.group(1) if m else line.rstrip()


def _reassemble(lines, i, max_cont=4):
    """Rejoin a message logcat split into multiple timestamped entries
    (long messages are chunked; chunks keep the same tag and prefix)."""
    buf = _strip_logcat_prefix(lines[i])
    j = i
    while buf.count("{") > buf.count("}") and j + 1 < len(lines) \
            and max_cont > 0:
        if "登录发送的数据" in lines[j + 1]:  # next marker, not a continuation
            break
        buf += _strip_logcat_prefix(lines[j + 1])
        j += 1
        max_cont -= 1
    return buf


def scan_log(path):
    """Returns (req_fields, resp_fields).

    req:  parsed from `登录发送的数据: k=v, ...` (the request the app sent);
          reassembled across logcat continuation lines before parsing.
    resp: fields found in decrypted `基类返回的数据：...` response lines —
          fallback when the request-marker line never appears (request bodies
          are only logged AES-encrypted, and some builds skip the marker).
    """
    req, resp = {}, {}
    # The log is raw UTF-8 from adb; decode explicitly — on Windows the
    # default text encoding is cp1252, which silently breaks the Chinese
    # marker match.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        if "登录发送的数据" in line:
            req = parse_payload(_reassemble(lines, i)) or req
        elif ("基类返回的数据" in line
              and ("phoneId" in line or '"state":"success"' in line)):
            resp.update(extract_json_fields(_reassemble(lines, i)))
    return req, resp


def scan_token(path):
    """Session token after a successful login. The app logs it in plaintext
    when connecting the chat websocket: .../webSocket/app/<hex>. cellmate2
    can use this directly (QIUI_TOKEN), so no login replay is needed."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = f.read()
    m = re.search(r"webSocket/app/([0-9a-fA-F]{24,})", data)
    if m:
        return m.group(1)
    m = re.search(r'"token"\s*:\s*"([0-9a-fA-F]{24,})"', data)
    return m.group(1) if m else ""


def parse_payload(line):
    """Parse the `k=v, k=v, ...` string following the 登录发送的数据 marker."""
    idx = line.find("登录发送的数据")
    if idx < 0:
        return {}
    rest = line[idx + len("登录发送的数据"):].strip()
    rest = rest.lstrip(":").strip()
    if rest.startswith("{"):
        rest = rest[1:]
    if rest.endswith("}"):
        rest = rest[:-1]
    d = {}
    for part in rest.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        d[k.strip()] = v.strip()
    return d


def write_creds(path, fields, userid):
    def g(k, default=""):
        return fields.get(k, default) or default
    lines = [
        "# Qiui login credentials (captured by capture_login.py).",
        "# Read by cellmate2cs and cellmate2 in place of environment vars.",
        "userName=%s" % g("userName", userid),
        "passWord=%s" % g("passWord"),
        "phoneId=%s" % g("phoneId"),
        "blackBox=%s" % g("blackBox"),
    ]
    if g("token"):
        lines.append("token=%s" % g("token"))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("[+] wrote credentials -> %s" % path)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 capture_login.py <userid> <password> "
              "[out-log-file] [creds-file]")
        return 2
    global EMAIL, PASSWD, OUT, CREDS
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    EMAIL = sys.argv[1]
    PASSWD = sys.argv[2]
    OUT = sys.argv[3] if len(sys.argv) > 3 else "./login_capture.log"
    CREDS = sys.argv[4] if len(sys.argv) > 4 else "./credentials.txt"

    print("[*] clearing logcat + app data")
    adb_shell("logcat -c")
    adb_shell("pm clear %s" % PKG)

    print("[*] starting logcat -> %s" % OUT)
    logf = open(OUT, "wb")
    log = subprocess.Popen([ADB, "logcat", "-v", "time"],
                           stdout=logf, stderr=subprocess.DEVNULL)
    try:
        print("[*] launching app")
        adb_shell("monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG)

        print("[*] waiting for privacy dialog (agree)")
        c = wait_for("agree", tries=15)
        if c:
            tap(*c)
        else:
            print("[!] agree not found (may have been auto-accepted)")

        print("[*] waiting for login screen")
        c = wait_for("login_number", tries=30)
        if not c:
            print("[!] login screen never appeared")
            return 1

        print("[*] entering email")
        tap(*find_center("login_number"))
        time.sleep(1)
        adb_shell("input text '%s'" % EMAIL)
        adb_shell("input keyevent 4")
        time.sleep(1)

        print("[*] entering password")
        tap(*find_center("login_password"))
        time.sleep(1)
        adb_shell("input text '%s'" % PASSWD)
        adb_shell("input keyevent 4")
        time.sleep(1)

        print("[*] ticking agreement checkbox")
        cbox = find_center("agreement_image")
        if not cbox:
            a = find_center("agreement")
            if a:
                cbox = (65, a[1])  # glyph sits left of the agreement text
        if cbox:
            tap(*cbox)
            time.sleep(1)
        else:
            print("[!] agreement checkbox not found")

        print("[*] tapping CONFIRM")
        c = find_center("loginButton")
        if not c:
            # e.g. a policy PDF viewer opened — go back to the login screen
            print("[!] loginButton missing — pressing back")
            for _ in range(3):
                adb_shell("input keyevent 4")
                time.sleep(1)
                c = find_center("loginButton")
                if c:
                    break
        if not c:
            print("[!] login screen not recoverable")
            return 1
        def count_123():
            with open(OUT, "r", encoding="utf-8", errors="replace") as f:
                return sum(1 for l in f if (" 123 " in l or "/TAG " in l))

        n0 = count_123()
        tap(*c)

        print("[*] waiting for login request/response (120s)")
        deadline = time.time() + 120
        confirm_t = time.time()
        retapped = False
        while time.time() < deadline:
            req, resp = scan_log(OUT)
            if req or resp:
                break
            if not retapped and time.time() > confirm_t + 30 \
                    and count_123() == n0:
                print("[!] no network activity after CONFIRM — "
                      "retrying checkbox + CONFIRM")
                if cbox:
                    tap(*cbox)
                    time.sleep(1)
                tap(*c)
                retapped = True
            time.sleep(1)

        if req or resp:
            print("[+] captured:")
            with open(OUT, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "登录发送的数据" in line or (
                            "基类返回的数据" in line and (req or resp)):
                        print(line.strip()[:300])
            print("[*] login request seen — waiting for session token (90s)")
            tok = ""
            tok_deadline = time.time() + 90
            while time.time() < tok_deadline:
                tok = scan_token(OUT)
                if tok:
                    break
                time.sleep(1)
            if tok:
                print("[+] session token: %s..." % tok[:12])
            else:
                print("[!] session token not found in log — cellmate2 will "
                      "fall back to login")
            fields = {}
            fields.update(resp)
            fields.update(req)
            fields.setdefault("passWord", PASSWD)
            if tok:
                fields["token"] = tok
            write_creds(CREDS, fields, EMAIL)
            return 0
        # Nothing matched — show what state the app is actually in so a
        # failed tap / unexpected screen is visible instead of a bare timeout.
        shot("./qiui_failed.png")
        print("[!] no login payload captured — current UI nodes:")
        for m in re.finditer(r'resource-id="([^"]*)"|text="([^"]{1,80})"',
                             dump_ui()):
            v = m.group(1) or m.group(2)
            if v:
                print("    " + v)
        print("[!] recent 123/TAG log lines:")
        with open(OUT, "r", encoding="utf-8", errors="replace") as f:
            tail = [l for l in f if (" 123 " in l or "/TAG " in l)][-40:]
        sys.stdout.writelines(tail)
        return 1
    finally:
        log.terminate()
        logf.close()


if __name__ == "__main__":
    sys.exit(main())
