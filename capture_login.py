#!/usr/bin/env python3
"""Automated Qiui app login capture via adb.

Drives the login UI (privacy dialog -> email / password / checkbox / CONFIRM)
and captures the app's real login payload from logcat
(tag 123, line "登录发送的数据: {...}").

Usage:
  python3 capture_login.py <userid> <password> [out-log-file] [creds-file]

Writes the captured login credentials (userName, passWord, phoneId, blackBox)
to creds-file (default ./credentials.txt), which the C# / C++ apps read.
"""
import re
import subprocess
import sys
import time

PKG = "cellmate.qiui.com"


def adb_shell(cmd, timeout=90):
    return subprocess.run(["adb", "shell", cmd], capture_output=True,
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
    r = subprocess.run(["adb", "exec-out", "screencap", "-p"],
                       capture_output=True)
    with open(path, "wb") as f:
        f.write(r.stdout)


def log_has_payload():
    with open(OUT, "rb") as f:
        return "登录发送的数据".encode() in f.read()


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
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("[+] wrote credentials -> %s" % path)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 capture_login.py <userid> <password> "
              "[out-log-file] [creds-file]")
        return 2
    global EMAIL, PASSWD, OUT, CREDS
    EMAIL = sys.argv[1]
    PASSWD = sys.argv[2]
    OUT = sys.argv[3] if len(sys.argv) > 3 else "./login_capture.log"
    CREDS = sys.argv[4] if len(sys.argv) > 4 else "./credentials.txt"

    print("[*] clearing logcat + app data")
    adb_shell("logcat -c")
    adb_shell("pm clear %s" % PKG)

    print("[*] starting logcat -> %s" % OUT)
    logf = open(OUT, "wb")
    log = subprocess.Popen(["adb", "logcat", "-v", "time"],
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
        _, ty = find_center("agreement")
        shot("./qiui_before.png")
        tap(65, ty)  # checkbox glyph left of the agreement text (x < 91)
        time.sleep(1)
        shot("./qiui_after.png")
        if open("./qiui_before.png", "rb").read() == \
                open("./qiui_after.png", "rb").read():
            print("[!] screenshot unchanged — tapping again")
            tap(65, ty)
            time.sleep(1)

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
        tap(*c)

        print("[*] waiting for 登录发送的数据 (90s)")
        deadline = time.time() + 90
        while time.time() < deadline:
            if log_has_payload():
                break
            time.sleep(1)

        if log_has_payload():
            print("[+] captured:")
            fields = {}
            with open(OUT, "r", errors="replace") as f:
                for line in f:
                    if "登录发送的数据" in line:
                        print(line.strip())
                        fields = parse_payload(line) or fields
            write_creds(CREDS, fields, EMAIL)
            return 0
        print("[!] timeout — no login payload captured")
        return 1
    finally:
        log.terminate()
        logf.close()


if __name__ == "__main__":
    sys.exit(main())
