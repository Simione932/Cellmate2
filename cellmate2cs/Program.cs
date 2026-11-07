// cellmate2cs — C#/.NET controller for the QIUI cellmate II (Gen2Lock, typeId 4)
//
// Keys/IV recovered from qiui.apk (see ../notes.md):
//   API key  87dQ_P5F#9&K*G6b9&f%8!d&06@(c_*a
//   PWD key  10kB8mdiaWRxFkNQD8Xtb6fm>Cg5N_QX
//   TS key   LpyaN2dvT3CbxRNJ>^*kjjAsq=^e*cD5   (EncryptUtil.TIME_STAMP, toyUid field)
//   IV       3*1&f6O%6&Pa5d_8
//
// Endpoints are all POST {base}/api/<path> with body = base64(AES-CBC(API_KEY, compact-json)),
// "token" header, and the User-Agent okhttp/4.10.0 (the server rejects other UAs).

using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SimpleSharpBLE;

namespace cellmate2cs;

internal static class Program
{
    // --------------------------------------------------------------- constants

    const string API_KEY = "87dQ_P5F#9&K*G6b9&f%8!d&06@(c_*a";
    const string PWD_KEY = "10kB8mdiaWRxFkNQD8Xtb6fm>Cg5N_QX";
    const string TS_KEY  = "LpyaN2dvT3CbxRNJ>^*kjjAsq=^e*cD5";
    const string BTA_KEY = "X7vuZ@NvjPtMmBF8bpWbbfrpYa3h11IB";
    const string CMD_KEY = "VfttrWZYZ5QVUe>})C5x?oYWVewxVy!]";
    const string IV      = "3*1&f6O%6&Pa5d_8";

    const string SVC_UUID = "0000ae3a-0000-1000-8000-00805f9b34fb";
    const string WR_UUID  = "0000ae3b-0000-1000-8000-00805f9b34fb";
    const string NT_UUID  = "0000ae3c-0000-1000-8000-00805f9b34fb";

    const string CONFIG_URL =
        "https://qiui-cn.oss-cn-shenzhen.aliyuncs.com/file/urlList/api.html";

    const string FALLBACK_BASE = "https://appapi.qiuitoy.com/";
    const string UA = "okhttp/4.10.0";

    // Captured working login payload (notes.md, logcat "登录发送的数据").
    // blackBox is single-use/session-scoped — recapture via phone logcat when
    // logins start failing (override with QIUI_BLACKBOX) - see capture_login.py.
    const string CAP_EMAIL      = "";
    const string CAP_PASSWD_B64 = "";
    const string CAP_BLACKBOX   = "";
    const string CAP_PHONEID    = "";

    // Manufacturer data (vendor 0x15F0) advertised by our board — stable per
    // device, unlike the rotating CoreBluetooth Address. The advertised NAME
    // (QIUI104) is shared by all cellmate devices, so the mfr payload is the
    // real discriminator. Capture with: cellmate2cs scan-dump
    const string CAP_MFR = "097a1aa5ca0a34";

    const string ENV_EMAIL    = "QIUI_EMAIL";
    const string ENV_PASSWORD = "QIUI_PASSWORD"; // plain password, AES-enc'd at login
    const string ENV_BLACKBOX = "QIUI_BLACKBOX";
    const string ENV_PHONEID  = "QIUI_PHONEID";
    const string ENV_UUID     = "QIUI_BLE_ID"; // advertised name, e.g. QIUI104
    const string ENV_MFR      = "QIUI_BLE_MFR"; // mfr data hex filter

    // Primary credential source: a key=value file written by capture_login.py.
    // Env vars and the CAP_* constants remain as fallbacks if the file is absent.
    const string CREDS_FILE = "credentials.txt";
    const string ENV_CREDS  = "QIUI_CREDENTIALS"; // path override

    static readonly HttpClient HTTP = new() { Timeout = TimeSpan.FromSeconds(30) };

    static int Main(string[] argv)
    {
        try
        {
            // Offline helpers use command-first syntax so no serial placeholder is
            // needed. Detect them by position (argv[0]); this also sidesteps the .NET
            // host eating a leading '-'. The '-' placeholder style still works below.
            if (argv.Length >= 1 && (argv[0] == "enc-pass" || argv[0] == "scan-dump"))
            {
                // Normalize to the normal <serial> <command> [args] shape so the
                // handlers below are the single implementation.
                var norm = new string[argv.Length + 1];
                norm[0] = "-";
                Array.Copy(argv, 0, norm, 1, argv.Length);
                argv = norm;
            }

            if (argv.Length < 2)
            {
                Console.WriteLine(
                    "Usage: cellmate2cs <serial|name-prefix> <command> [args]" + Environment.NewLine +
                    "  commands: devices | token | unlock [role] | lock | clear-shock |" + Environment.NewLine +
                    "            clear-timed-unlock | full (token+unlock+lock) |" + Environment.NewLine +
                    "            shock [secs=10] [volt=1] [mode=1..3] (timed) |" + Environment.NewLine +
                    "            shock-now [secs=1] [volt=1] [mode=1..3] (immediate) |" + Environment.NewLine +
                    "            lock-timer list | status | set <minutes> | cancel [id] [type]" + Environment.NewLine +
                    "  offline:   enc-pass '<plain password>' | scan-dump [rounds=2]" + Environment.NewLine +
                    "            (command-first form, no login needed)" + Environment.NewLine +
                    "Credentials: ./credentials.txt (see README.md); env overrides:" + Environment.NewLine +
                    "Env: " + ENV_EMAIL + " " + ENV_PASSWORD + " " + ENV_BLACKBOX + " " + ENV_PHONEID + " " + ENV_UUID + " " + ENV_MFR + " QIUI_CREDENTIALS");
                return 1;
            }

            // Normal invocation is <serial|name-prefix> <command> [args].
            // argv is already the application's argument list; there is no
            // executable-name slot to skip.
            string sel = argv[0];
            string cmd = argv[1];

            // Offline helper: encrypt a plain password the way the app does
            // (AES-256-CBC, PWD_KEY, fixed IV) and print the base64 form.
            //   cellmate2cs - enc-pass 'myPassword'
            if (cmd == "enc-pass")
            {
                if (argv.Length < 3)
                {
                    Console.WriteLine("Usage: cellmate2cs [serial] enc-pass '<plain password>'");
                    return 1;
                }
                Console.WriteLine(AesEnc(PWD_KEY, argv[2]));
                return 0;
            }

            if (cmd == "scan-dump")
            {
                ScanDump(ArgInt(argv, 2, 2, "rounds"));
                return 0;
            }

            string base_url = GetBaseUrl();
            Console.WriteLine("[*] base URL: " + base_url);
            string token = DoLogin(base_url);

            if (cmd == "devices")
            {
                JsonElement j = ApiGet(base_url,
                    "api/feign/toyUserBinding/getUserBindingToyDevices", token);
                if ((j.GetProperty("state").GetString() ?? "") != "success")
                    throw new Exception("device list failed: " + j.GetRawText());
                foreach (var d in j.GetProperty("data").EnumerateArray())
                    Console.WriteLine("    " + (d.TryGetProperty("toyName", out var n) ? n.GetString() : "?")
                        + "  sn=" + (d.TryGetProperty("serialNumber", out var s) ? s.GetString() : "?")
                        + "  typeId=" + (d.TryGetProperty("typeId", out var t) ? t.GetInt32() : 0)
                        + "  role=" + (d.TryGetProperty("toyRole", out var r) ? r.GetInt32() : 0));
                return 0;
            }

            Device dev = PickDevice(base_url, token, sel);
            if (dev.TypeId != 4)
                Console.WriteLine("[!] warning: typeId=" + dev.TypeId + " (expected 4 for cellmate II)");

            // Lock timer: pure server-side (toyUid only), no BLE needed.
            if (cmd == "lock-timer")
            {
                RunLockTimer(base_url, token, dev,
                    argv.Length > 2 ? argv[2] : "list",
                    ArgLong(argv, 3, 0L, "id"),
                    argv.Length > 4 ? argv[4] : "");
                return 0;
            }

            string uuid = EnvOr(ENV_UUID, "QIUI104");
            string mfr = EnvOr(ENV_MFR, CAP_MFR);
            Peripheral periph = BleSetup(uuid, mfr);
            g_periph = periph;
            Console.WriteLine("[*] BLE connected, notify on ae3c enabled");

            PrimeBinding(base_url, token, dev);

            if (cmd == "token")
                RunCommand(base_url, token, dev, "api/feign/toyCellmateBluetooth/getToyToken",
                    new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }});
            else if (cmd == "unlock")
            {
                int role = ArgInt(argv, 2, dev.Role, "role");
                RunCommand(base_url, token, dev, "api/feign/toyBluetooth/unlockToy",
                    new Dictionary<string, object>
                    {
                        { "unLockType", "0" }, { "type", role }, { "toyUid", EncToyuid(dev.ToyId) },
                    });
            }
            else if (cmd == "lock")
                RunCommand(base_url, token, dev, "api/feign/toyCellmateBluetooth/toyCloseLock",
                    new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }});
            else if (cmd == "clear-shock")
                RunCommand(base_url, token, dev, "api/feign/toyCellmateBluetooth/clearToyTimingElectricShock",
                    new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }});
            else if (cmd == "clear-timed-unlock")
                RunCommand(base_url, token, dev, "api/feign/toyCellmateBluetooth/clearToyUnlockTimingTime",
                    new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }});
            else if (cmd == "shock")
                RunShock(base_url, token, dev,
                    ArgInt(argv, 2, 10, "secs"), ArgInt(argv, 3, 1, "volt"), ArgInt(argv, 4, 1, "mode"));
            else if (cmd == "shock-now")
                RunShockNow(base_url, token, dev,
                    ArgInt(argv, 2, 1, "secs"), ArgInt(argv, 3, 1, "volt"), ArgInt(argv, 4, 1, "mode"));
            else if (cmd == "full")
            {
                RunCommand(base_url, token, dev, "api/feign/toyCellmateBluetooth/getToyToken",
                    new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}, 2000);
                int role = ArgInt(argv, 2, dev.Role, "role");
                RunCommand(base_url, token, dev, "api/feign/toyBluetooth/unlockToy",
                    new Dictionary<string, object> { { "unLockType", "0" }, { "type", role }, { "toyUid", EncToyuid(dev.ToyId) } }, 2000);
                RunCommand(base_url, token, dev, "api/feign/toyCellmateBluetooth/toyCloseLock",
                    new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }});
            }
            else
                throw new Exception("unknown command " + cmd);

            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine("[!] " + e);
            return 1;
        }
        finally
        {
            g_periph?.Dispose();
            g_periph = null;
            HTTP.Dispose();
        }
    }

    // --------------------------------------------------------------- helpers

    static string EnvOr(string name, string def)
    {
        string? v = Environment.GetEnvironmentVariable(name);
        return v is null ? def : v;
    }

    // Optional integer argv slot: default if absent, clear error if not an int.
    static int ArgInt(string[] argv, int i, int def, string what)
    {
        if (i >= argv.Length) return def;
        if (!int.TryParse(argv[i], out int v))
            throw new Exception("invalid " + what + ": '" + argv[i] + "' (expected integer)");
        return v;
    }

    static long ArgLong(string[] argv, int i, long def, string what)
    {
        if (i >= argv.Length) return def;
        if (!long.TryParse(argv[i], out long v))
            throw new Exception("invalid " + what + ": '" + argv[i] + "' (expected integer)");
        return v;
    }

    // Read userName/passWord/phoneId/blackBox from the captured-credentials file.
    // Returns empty strings for any field absent (caller falls back to env/CAP_*).
    static (string user, string pass, string phone, string black) LoadCreds()
    {
        string path = EnvOr(ENV_CREDS, CREDS_FILE);
        string u = "", p = "", ph = "", bb = "";
        if (!File.Exists(path)) return (u, p, ph, bb);
        foreach (var line in File.ReadAllLines(path))
        {
            int i = line.IndexOf('=');
            if (i < 0) continue;
            string k = line[..i].Trim();
            string v = line[(i + 1)..].Trim();
            switch (k)
            {
                case "userName": u = v; break;
                case "passWord": p = v; break;
                case "phoneId": ph = v; break;
                case "blackBox": bb = v; break;
            }
        }
        return (u, p, ph, bb);
    }

    static bool Debug => Environment.GetEnvironmentVariable("QIUI_DEBUG") is not null;

    // Serialize a compact JSON object (matches the app's nlohmann compact dump,
    // which the server parses). Order is preserved by insertion order.
    static string JsonObj(Dictionary<string, object> obj)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            foreach (var kv in obj)
            {
                w.WritePropertyName(kv.Key);
                WriteValue(w, kv.Value);
            }
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    static void WriteValue(Utf8JsonWriter w, object v)
    {
        switch (v)
        {
            case string s: w.WriteStringValue(s); break;
            case int i: w.WriteNumberValue(i); break;
            case long l: w.WriteNumberValue(l); break;
            case bool b: w.WriteBooleanValue(b); break;
            default: w.WriteStringValue(v.ToString()); break;
        }
    }

    // ---------------------------------------------------------------- crypto

    // AES-CBC, PKCS#7, 16/24/32-byte key. enc=true encrypt, false decrypt.
    static byte[] AesCbc(string key, string iv, byte[] in_, bool enc)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = Encoding.UTF8.GetBytes(iv);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var t = enc ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return t.TransformFinalBlock(in_, 0, in_.Length);
    }

    static string AesEnc(string key, string data)
        => Convert.ToBase64String(AesCbc(key, IV, Encoding.UTF8.GetBytes(data), true));

    // The server wraps API responses in a JSON string literal ("<base64>").
    static byte[] FromBase64Lenient(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
                sb.Append(c);
        }
        if (sb.Length == 0) throw new Exception("empty base64 payload");
        try { return Convert.FromBase64String(sb.ToString()); }
        catch (FormatException)
        {
            throw new Exception("invalid base64 payload: " + s);
        }
    }

    static string AesDec(string key, string b64)
        => Encoding.UTF8.GetString(AesCbc(key, IV, FromBase64Lenient(b64), false));

    // The device list's toyUid is itself b64(AES(TS_KEY, "<raw_id>_<ms>")) —
    // decrypt it and take the prefix before '_' to get the raw toy ID.
    static string RawToyId(string list_toyuid)
    {
        string pt = AesDec(TS_KEY, list_toyuid);
        int p = pt.IndexOf('_');
        return p < 0 ? pt : pt[..p];
    }

    // The device list's bluetoothAddress is b64(AES(BTA_KEY, "<MAC>")) — plaintext MAC.
    static string RawMac(string list_bta) => AesDec(BTA_KEY, list_bta);

    // Command responses carry the 32-hex BLE command either plaintext or as
    // b64(AES(CMD_KEY, <32-hex>)) — normalize to the 32-hex form.
    static string DecodeCommand(string data)
    {
        if (data.Length == 32 && data.All(c => IsHexChar(c))) return data;
        byte[] pt = AesCbc(CMD_KEY, IV, FromBase64Lenient(data), false);
        return Encoding.UTF8.GetString(pt);
    }

    static bool IsHexChar(char c)
        => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    // toyUid wire form: b64(AES(TS_KEY, <raw_id>_<now_ms>))
    static string EncToyuid(string raw_id)
        => AesEnc(TS_KEY, raw_id + "_" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    // ---------------------------------------------------------------- http

    // POST a compact-JSON object to a closed-backend path; returns decrypted JSON.
    static JsonElement ApiPost(string base_url, string path, string body, string token)
    {
        string enc = AesEnc(API_KEY, body);
        if (Debug)
        {
            // Mirrors the app's logcat "jsonObject:" line for easy diffing.
            Console.Error.WriteLine("[debug] POST " + base_url + path);
            Console.Error.WriteLine("[debug]   token: " + token);
            Console.Error.WriteLine("[debug]   body: " + enc);
        }

        using var req = new HttpRequestMessage(HttpMethod.Post, base_url + path)
        {
            Content = new StringContent(enc, Encoding.UTF8, "application/json"),
        };

        req.Headers.TryAddWithoutValidation("User-Agent", UA);
        AddToken(req, token);

        using HttpResponseMessage resp = HTTP.Send(req);
        long status = (long)resp.StatusCode;
        string raw = resp.Content.ReadAsStringAsync().Result;
        if (status != 200)
            throw new Exception("HTTP " + status + " from " + path);

        return Parse(AesDec(API_KEY, raw));
    }

    // GET a closed-backend path (no body) — e.g. the device list
    static JsonElement ApiGet(string base_url, string path, string token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, base_url + path);
        req.Headers.TryAddWithoutValidation("User-Agent", UA);
        AddToken(req, token);

        using HttpResponseMessage resp = HTTP.Send(req);
        long status = (long)resp.StatusCode;
        string raw = resp.Content.ReadAsStringAsync().Result;
        if (status != 200)
            throw new Exception("HTTP " + status + " from " + path);

        return Parse(AesDec(API_KEY, raw));
    }

    static void AddToken(HttpRequestMessage req, string token)
    {
        if (!string.IsNullOrEmpty(token))
            req.Headers.TryAddWithoutValidation("token", token);
    }

    static JsonElement Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // JsonElement has no Contains() everywhere, so wrap TryGetProperty.
    static bool Has(JsonElement p, string name)
        => p.ValueKind == JsonValueKind.Object && p.TryGetProperty(name, out _);

    static string GetBaseUrl()
    {
        string raw;
        try
        {
            using var resp = HTTP.GetAsync(CONFIG_URL).Result;
            raw = resp.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            Console.WriteLine("[!] config fetch failed; using fallback");
            return FALLBACK_BASE;
        }
        try
        {
            string txt = AesDec(API_KEY, raw);
            // Real format: CH_HTTP_URL="appapi.qiuitoy.com/api",... — search
            // for the full key, not the "HTTP_URL" substring it contains.
            const string KEY = "CH_HTTP_URL=";
            int p = txt.IndexOf(KEY, StringComparison.Ordinal);
            if (p < 0) return FALLBACK_BASE;
            p += KEY.Length;

            // The value is double-quoted; if so, search for the CLOSING quote
            // from p+1. Otherwise take up to the first delimiter.
            string host;
            if (p < txt.Length && txt[p] == '"')
            {
                int q = txt.IndexOf('"', p + 1);
                if (q < 0) return FALLBACK_BASE;
                host = txt[(p + 1)..q];
            }
            else
            {
                int q = txt.IndexOfAny(new[] { ',', ' ', '"', '\n', '\r', ';', ')' }, p);
                host = q < 0 ? txt[p..] : txt[p..q];
            }

            if (host.Length == 0) return FALLBACK_BASE;

            int a = host.IndexOf("/api");
            if (a >= 0) host = host[..a];
            return "https://" + host + "/";
        }
        catch
        {
            return FALLBACK_BASE;
        }
    }

    // ---------------------------------------------------------------- api flow

    sealed class Device
    {
        public string ToyUid = "";   // encrypted b64 as returned by the device list
        public string ToyId = "";    // raw toy ID (TS-decrypted, prefix before '_')
        public string Mac = "";      // raw MAC (BTA-decrypted)
        public string Serial = "";
        public int Role = 1;
        public int TypeId = 4;
    }

    static string DoLogin(string base_url)
    {
        var (cu, cp, cph, cbb) = LoadCreds();
        string envPass = EnvOr(ENV_PASSWORD, "");
        string user = cu.Length > 0 ? cu : EnvOr(ENV_EMAIL, CAP_EMAIL);
        string pass = cp.Length > 0 ? cp
            : (envPass.Length == 0 ? CAP_PASSWD_B64 : AesEnc(PWD_KEY, envPass));
        if (user.Length == 0 && pass.Length == 0)
            throw new Exception("no credentials: create ./credentials.txt (see capture_login.py) " +
                                "or set " + ENV_EMAIL + "/" + ENV_PASSWORD);
        var body = new Dictionary<string, object>
        {
            { "platformType", "2" },
            { "userName", user },
            { "versionNum", "7.0.38" },
            { "registrationId", "" },
            { "loginType", "3" },
            { "passWord", pass },
            { "appLanguage", 2 },
            { "phoneId", cph.Length > 0 ? cph : EnvOr(ENV_PHONEID, CAP_PHONEID) },
            { "blackBox", cbb.Length > 0 ? cbb : EnvOr(ENV_BLACKBOX, CAP_BLACKBOX) },
            { "deviceType", "2" },
        };

        JsonElement j = ApiPost(base_url, "api/feign/userInfo/login", JsonObj(body), "");
        if (Debug) Console.Error.WriteLine("[debug] login response: " + j.GetRawText());
        string state = j.GetProperty("state").GetString() ?? "";
        if (state != "success")
            throw new Exception("login failed: " + j.GetRawText());

        JsonElement data = j.GetProperty("data");
        string token = data.GetProperty("token").GetString() ?? "";
        if (string.IsNullOrEmpty(token))
            throw new Exception("login failed: no token in response");

        long uid = data.GetProperty("uid").GetInt64();
        Console.WriteLine("[+] logged in uid=" + uid);
        return token;
    }

    static Device PickDevice(string base_url, string token, string sel)
    {
        JsonElement j = ApiGet(base_url,
            "api/feign/toyUserBinding/getUserBindingToyDevices", token);
        if ((j.GetProperty("state").GetString() ?? "") != "success")
            throw new Exception("device list failed: " + j.GetRawText());
        foreach (JsonElement d in j.GetProperty("data").EnumerateArray())
        {
            string sn = d.TryGetProperty("serialNumber", out var se) ? (se.GetString() ?? "") : "";
            string name = d.TryGetProperty("toyName", out var ne) ? (ne.GetString() ?? "") : "";
            if (sn == sel || name.StartsWith(sel))
            {
                int typeId = Has(d, "typeId") ? d.GetProperty("typeId").GetInt32() : 4;
                Console.WriteLine("[+] device: " + name + " sn=" + sn + " typeId=" + typeId);
                var dev = new Device
                {
                    ToyUid = d.GetProperty("toyUid").GetString() ?? "",
                    ToyId = RawToyId(d.GetProperty("toyUid").GetString() ?? ""),
                    Mac = Has(d, "bluetoothAddress")
                        ? RawMac(d.GetProperty("bluetoothAddress").GetString() ?? "") : "",
                    Serial = sn,
                    Role = Has(d, "toyRole") ? d.GetProperty("toyRole").GetInt32() : 1,
                    TypeId = typeId,
                };

                Console.WriteLine("[+] raw toyId=" + dev.ToyId + " mac=" + dev.Mac);
                return dev;
            }
        }
        throw new Exception("no device matching '" + sel + "'");
    }

    // ---------------------------------------------------------------- ble

    static Peripheral? g_periph;

    static string ToHex(byte[] in_)
    {
        const string h = "0123456789ABCDEF";
        var sb = new StringBuilder(in_.Length * 2);
        foreach (byte b in in_)
        {
            sb.Append(h[b >> 4]);
            sb.Append(h[b & 15]);
        }
        return sb.ToString();
    }

    static byte[] FromHex(string s)
    {
        if (s.Length % 2 != 0) throw new Exception("odd-length hex");

        var out_ = new byte[s.Length / 2];
        for (int i = 0; i < out_.Length; i++)
        {
            int hi = HexVal(s[i * 2]);
            int lo = HexVal(s[i * 2 + 1]);
            if (hi < 0 || lo < 0) throw new Exception("bad hex: " + s);

            out_[i] = (byte)((hi << 4) | lo);
        }
        return out_;
    }

    static int HexVal(char c)
        => c is >= '0' and <= '9' ? c - '0'
          : c is >= 'a' and <= 'f' ? c - 'a' + 10
          : c is >= 'A' and <= 'F' ? c - 'A' + 10
          : -1;

    static void WaitFor(Func<bool> pred, int timeout_s, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeout_s);
        while (!pred())
        {
            if (DateTime.UtcNow > deadline)
                throw new Exception("timed out waiting for " + what);
            Thread.Sleep(100);
        }
    }

    // Concatenated hex of all advertised manufacturer-data payloads.
    static string MfrHex(Peripheral p)
    {
        var sb = new StringBuilder();
        foreach (var kv in p.ManufacturerData ?? new Dictionary<ushort, byte[]>())
            sb.Append(kv.Value is not null ? ToHex(kv.Value) : "");
        return sb.ToString();
    }

    // Match by advertised name AND (if mfr_filter is non-empty) manufacturer
    // data — all cellmate boards share the name QIUI104. On macOS Peripheral
    // Identifier is the advertised name and Address is the rotating CoreBluetooth
    // UUID, so Identifier is the right field here.
    static Peripheral BleSetup(string uuid, string mfr_filter)
    {
        var adapters = Adapter.GetAdapters();
        Peripheral? match = null;
        var scanned = new List<Peripheral>();
        try
        {
            if (adapters.Count == 0)
                throw new Exception("no Bluetooth adapter found");

            Adapter adapter = adapters[0];

            string target = uuid.ToLowerInvariant();
            string mfr = mfr_filter.ToLowerInvariant();
            for (int round = 1; round <= 3 && match is null; round++)
            {
                adapter.ScanFor(TimeSpan.FromSeconds(5));
                var perips = adapter.ScanGetResults();
                foreach (var p in perips)
                {
                    string id = (p.Identifier ?? "").ToLowerInvariant();
                    string pmfr = MfrHex(p);
                    bool match_id = id == target;
                    // Exact match on a single manufacturer payload: the
                    // concatenated form lets a short filter false-positive on
                    // an adjacent payload's bytes.
                    bool match_mfr = string.IsNullOrEmpty(mfr);
                    if (!match_mfr)
                        foreach (var kv in p.ManufacturerData ?? new Dictionary<ushort, byte[]>())
                            if (kv.Value is not null &&
                                ToHex(kv.Value).Equals(mfr, StringComparison.OrdinalIgnoreCase))
                                match_mfr = true;
                    if (match_id)
                        Console.WriteLine($"[*] scanned {p.Identifier} addr={p.Address} mfr={pmfr}"
                            + (match_mfr ? "  <- match" : ""));
                    if (match_id && match_mfr)
                        match = p;
                    if (!scanned.Contains(p))
                        scanned.Add(p);
                }

                if (match is null)
                    Console.WriteLine("[*] round " + round + ": not found, retrying");
            }

            if (match is null)
                throw new Exception("device " + uuid +
                    (string.IsNullOrEmpty(mfr) ? "" : " (mfr " + mfr + ")") +
                    " not found in scan — device powered on and in range?");

            try
            {
                match.Connect();
                WaitFor(() => match.IsConnected, 15, "BLE connection");
                Console.WriteLine("[*] connected to " + match.Identifier + " (" + match.Address + ")");

                // Verify the GATT characteristics we need exist before subscribing.
                EnsureCharacteristic(match, SVC_UUID, WR_UUID);
                EnsureCharacteristic(match, SVC_UUID, NT_UUID);
                return match;
            }
            catch
            {
                // Don't leak a connected peripheral on a GATT lookup failure.
                match.Dispose();
                throw;
            }
        }
        finally
        {
            // Adapters are process-lifetime singletons (as in the C++ twin) —
            // disposing one would kill the connection we just returned. Drop
            // every scanned peripheral except the one we keep.
            foreach (var p in scanned)
                if (!ReferenceEquals(p, match))
                    p.Dispose();
        }
    }

    static Service? FindService(Peripheral p, string uuid)
    {
        foreach (var s in p.Services)
            if (string.Equals(s.Uuid, uuid, StringComparison.OrdinalIgnoreCase))
                return s;
        return null;
    }

    static void EnsureCharacteristic(Peripheral p, string svcUuid, string chrUuid)
    {
        Service? s = FindService(p, svcUuid);
        if (s is null) throw new Exception("service " + svcUuid + " not found");
        foreach (var c in s.Characteristics)
            if (string.Equals(c.Uuid, chrUuid, StringComparison.OrdinalIgnoreCase))
                return;
        throw new Exception("characteristic " + chrUuid + " not found in service " + svcUuid);
    }

    static void ScanDump(int rounds)
    {
        var adapters = Adapter.GetAdapters();
        if (adapters.Count == 0)
            throw new Exception("no Bluetooth adapter found");

        Adapter adapter = adapters[0];
        {
            var seen = new HashSet<string>();
            for (int round = 1; round <= rounds; round++)
            {
                adapter.ScanFor(TimeSpan.FromSeconds(5));
                var perips = adapter.ScanGetResults();
                foreach (var p in perips)
                {
                    var sb = new StringBuilder();
                    sb.Append("name=" + (p.Identifier ?? "?"));
                    sb.Append(" addr=" + (p.Address ?? "?"));
                    sb.Append(" type=" + (int)p.AddressType);
                    sb.Append(" rssi=" + p.Rssi);
                    foreach (var kv in p.ManufacturerData ?? new Dictionary<ushort, byte[]>())
                        sb.Append(" mfr=" + kv.Key.ToString("X4") + ":" + ToHex(kv.Value));

                    string line = sb.ToString();
                    if (seen.Add(line))
                        Console.WriteLine(line);
                    p.Dispose();
                }
            }
        }
    }

    // Write 16 bytes (32-hex) to ae3b and wait for the 16-byte reply on ae3c.
    static async Task<string> WriteAndWait(Peripheral p, string hex, int timeout_s = 15)
    {
        var tcs = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        // BLE notifications are not guaranteed to be delivered exactly once,
        // and a residual notification from a previous command can still be in
        // flight when we subscribe. Gate the TCS on the write being dispatched,
        // and rely on TrySetResult to absorb duplicates and late notifications.
        int gate = 0;
        p.Notify(SVC_UUID, NT_UUID, bytes =>
        {
            if (Volatile.Read(ref gate) == 1) tcs.TrySetResult(bytes);
        });
        try
        {
            byte[] bytes = FromHex(hex);

            // Open the gate only AFTER the write is dispatched: a residual can
            // arrive while WriteCommand is still in flight, and accepting it
            // would be a wrong reply. A real reply cannot arrive before the
            // write goes out, so the miss window shrinks to the instant between
            // WriteCommand returning and the gate write.
            p.WriteCommand(SVC_UUID, WR_UUID, bytes);
            Volatile.Write(ref gate, 1);
            byte[] reply;
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeout_s)))
            {
                try
                {
                    reply = await tcs.Task.WaitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    throw new Exception("no BLE reply within " + timeout_s + " s");
                }
            }
            if (reply.Length != 16)
                Console.Error.WriteLine("[!] warning: expected 16-byte BLE reply, got " + reply.Length);
            return ToHex(reply);
        }
        finally
        {
            try { p.Unsubscribe(SVC_UUID, NT_UUID); }
            catch { }
        }
    }

    // ---------------------------------------------------------------- commands

    static void PostDecry(string base_url, string token, Device dev, string reply_hex)
    {
        // The app sends the reply hex AES-encrypted with the BLUETOOTH_COMMAND
        // key (EncryptUtil.g(BLUETOOTH_COMMAND, str)), not raw.
        var body = new Dictionary<string, object>
        {
            { "lockCommand", AesEnc(CMD_KEY, reply_hex) },
            { "toyUid", EncToyuid(dev.ToyId) },
        };

        JsonElement j = ApiPost(base_url,
            "api/feign/toyCellmateBluetooth/decryBluetoothCommand", JsonObj(body), token);
        if ((j.GetProperty("state").GetString() ?? "") == "success" && Has(j, "data"))
            Console.WriteLine($"    reply {reply_hex} -> {j.GetProperty("data").GetRawText()}");
        else
            Console.WriteLine($"    reply {reply_hex} -> (raw) {j.GetRawText()}");
    }

    // Prime the server's toy state (the app does this right after BLE connect,
    // before minting a token): raw MAC + TS-enc toyUid.
    static void PrimeBinding(string base_url, string token, Device dev)
    {
        var body = new Dictionary<string, object>
        {
            { "bluetoothAddress", dev.Mac },
            { "toyUid", EncToyuid(dev.ToyId) },
        };
        try
        {
            JsonElement j = ApiPost(base_url,
                "api/feign/toyUserBinding/getToyBindingInfoDetail", JsonObj(body), token);
            Console.WriteLine("[*] getToyBindingInfoDetail: " + (j.GetProperty("state").GetString() ?? "?"));
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("[!] getToyBindingInfoDetail: " + e.Message);
        }
    }

    // Fetch a 32-hex command from the server, write it to the device, wait for
    // the 16-byte reply, decrypt it server-side, print the result.
    // Retry token minting a few times
    static void RunCommand(string base_url, string token, Device dev, string path,
        Dictionary<string, object> body, int settle_ms = 1000)
    {
        JsonElement j = default!;
        for (int attempt = 1;; attempt++)
        {
            j = ApiPost(base_url, path, JsonObj(body), token);
            if ((j.GetProperty("state").GetString() ?? "") == "success" && Has(j, "data"))
                break;

            if (attempt >= 3)
                throw new Exception(path + " failed: " + j.GetRawText());

            Console.Error.WriteLine($"[!] {path} attempt {attempt} failed: {j.GetRawText()} — retrying");
            Thread.Sleep(1000);
        }
        string hex = DecodeCommand(j.GetProperty("data").GetString() ?? "");
        Console.WriteLine("[*] " + path + " -> " + hex);
        string reply = WriteAndWait(g_periph!, hex).Result;
        PostDecry(base_url, token, dev, reply);
        Thread.Sleep(settle_ms);
    }

    // Shock: save a timed-shock record (Gen2LockTimedElectricShockActivity.r0),
    // sync it to get the minted lockCommand(s), write them to the device,
    // decrypt each reply. Ranges from the app UI: 1-20 s, volt 1-4, mode 1-3.
    static void RunShock(string base_url, string token, Device dev, int secs, int volt, int mode)
    {
        if (secs < 1 || secs > 20) throw new Exception("shock duration must be 1-20 s");
        if (volt < 1 || volt > 4) throw new Exception("shockVolt must be 1-4");
        if (mode < 1 || mode > 3)
            throw new Exception("electricMode must be 1-3 (1 vibrate, 2 tremble, 3 sting)");

        // beginElectricTime is a RELATIVE offset from now, in seconds
        // (server sets begin = now + bet*1000). The app rejects 0 (00:00:00),
        // so the minimum is 1 minute. Start ~1 min out so the command is minted
        // shortly after we begin polling.
        const int bet = 60;
        var body = new Dictionary<string, object>
        {
            { "electricShockTime", secs },
            { "electricMode", mode },
            { "shockVolt", volt },
            { "beginElectricTime", bet },
            { "toyUid", EncToyuid(dev.ToyId) },
        };

        JsonElement j = ApiPost(base_url,
            "api/feign/toyElectricTimingRecord/saveElectricTimingRecord", JsonObj(body), token);

        if ((j.GetProperty("state").GetString() ?? "") != "success")
            throw new Exception("saveElectricTimingRecord failed: " + j.GetRawText());

        Console.WriteLine("[+] shock saved (" + secs + "s volt=" + volt + " mode=" + mode +
            "), starts in " + bet + "s");

        // The app always syncs right after a successful token write — the server
        // appears to only mint shock commands for toys that just authenticated.
        {
            JsonElement tj = ApiPost(base_url,
                "api/feign/toyCellmateBluetooth/getToyToken",
                JsonObj(new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}), token);

            if ((tj.GetProperty("state").GetString() ?? "") != "success" || !Has(tj, "data"))
                throw new Exception("getToyToken failed: " + tj.GetRawText());

            string hex = DecodeCommand(tj.GetProperty("data").GetString() ?? "");
            Console.WriteLine("[*] token -> " + hex);
            string reply = WriteAndWait(g_periph!, hex).Result;
            PostDecry(base_url, token, dev, reply);
            Thread.Sleep(1000);
        }

        // The server mints a real (non-zero) lockCommand once the start time
        // arrives; before that it returns an all-zero placeholder. Poll sync
        // until a real command shows up.
        int n = 0;
        var deadline = DateTime.UtcNow.AddSeconds(bet + 120);
        for (;;)
        {
            JsonElement s = ApiPost(base_url,
                "api/feign/toyElectricTimingRecord/synchronizeElectricTimingRecord",
                JsonObj(new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}), token);

            if ((s.GetProperty("state").GetString() ?? "") != "success")
                throw new Exception("synchronizeElectricTimingRecord failed: " + s.GetRawText());

            bool got = false;
            foreach (JsonElement r in s.GetProperty("data").EnumerateArray())
            {
                string lc = r.GetProperty("lockCommand").GetString() ?? "";
                if (string.IsNullOrEmpty(lc) || r.GetProperty("electricShockTime").GetInt32() == 0) continue;
                string hex = DecodeCommand(lc);
                if (!NonZero(hex)) continue; // not due yet

                Console.WriteLine("[*] shock command " + (++n) + " -> " + hex);
                string reply = WriteAndWait(g_periph!, hex).Result;
                PostDecry(base_url, token, dev, reply);
                // Remove the record so it can't resurface in a later sync.
                if (Has(r, "uid"))
                {
                    try
                    {
                        ApiPost(base_url,
                            "api/feign/toyElectricTimingRecord/deleteElectricTimingRecord",
                            JsonObj(new Dictionary<string, object>
                            {
                                { "uid", r.GetProperty("uid").GetString()! },
                                { "toyUid", EncToyuid(dev.ToyId) },
                            }), token);
                    }
                    catch (Exception de)
                    {
                        Console.Error.WriteLine("[!] deleteElectricTimingRecord failed " +
                                                "(record may resurface in a later sync): " + de.Message);
                    }
                }
                Thread.Sleep(1000);
                got = true;
            }

            if (got) break;

            if (DateTime.UtcNow > deadline)
                throw new Exception("shock command never minted (start time passed?)");

            Thread.Sleep(2000);
        }
    }

    // Immediate shock (app: Gen2Lock "heart" shock, nb/u.java Q()). Unlike the
    // timed flow there is NO save/sync/delete and NO beginElectricTime: a POST to
    // getToyShockImmediately returns a command we write straight to ae3b; we re-send
    // it roughly once per second to sustain the effect for `secs` seconds. Body is
    // {shockModel, shockVolt, toyUid} (note shockModel, not electricMode). The app
    // only reaches this after the connect/token priming, so mirror that here with a
    // getToyToken round-trip first.
    static void RunShockNow(string base_url, string token, Device dev,
                            int secs, int volt, int mode)
    {
        if (secs < 1) throw new Exception("shock duration must be >= 1 s");
        if (volt < 1 || volt > 4) throw new Exception("shockVolt must be 1-4");
        if (mode < 1 || mode > 3)
            throw new Exception("shockModel must be 1-3 (1 vibrate, 2 tremble, 3 sting)");

        // Prime server state with a token write (the app has already run this on
        // connect; the timed-mint notes show the server only mints for toys that
        // just authenticated). Writing getToyToken's command is a benign battery
        // readback ({battery, commandCode:"13"}), not an unlock/lock.
        {
            JsonElement tj = ApiPost(base_url,
                "api/feign/toyCellmateBluetooth/getToyToken",
                JsonObj(new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}), token);
            if ((tj.GetProperty("state").GetString() ?? "") != "success" || !Has(tj, "data"))
                throw new Exception("getToyToken failed: " + tj.GetRawText());
            string thex = DecodeCommand(tj.GetProperty("data").GetString() ?? "");
            Console.WriteLine("[*] token -> " + thex);
            string treply = WriteAndWait(g_periph!, thex).Result;
            PostDecry(base_url, token, dev, treply);
            Thread.Sleep(1000);
        }

        // Mint the immediate command ONCE, then re-send the same 32-hex to the
        // board roughly once per second for `secs` seconds (no re-minting).
        JsonElement j = ApiPost(base_url,
            "api/feign/toyCellmateBluetooth/getToyShockImmediately",
            JsonObj(new Dictionary<string, object>
            {
                { "shockModel", mode },
                { "shockVolt", volt },
                { "toyUid", EncToyuid(dev.ToyId) },
            }), token);
        if ((j.GetProperty("state").GetString() ?? "") != "success" || !Has(j, "data"))
            throw new Exception("getToyShockImmediately failed: " + j.GetRawText());
        string hex = DecodeCommand(j.GetProperty("data").GetString() ?? "");
        Console.WriteLine("[+] immediate shock command -> " + hex);

        var deadline = DateTime.UtcNow.AddSeconds(secs);
        for (int n = 0; ; )
        {
            string reply = WriteAndWait(g_periph!, hex).Result;
            PostDecry(base_url, token, dev, reply);
            if (n > 0) Console.WriteLine("[*] resend " + n + " -> " + reply);
            if (DateTime.UtcNow >= deadline) break;
            Thread.Sleep(1000);
            n++;
        }
    }

    static bool NonZero(string h)
    {
        foreach (char c in h) if (c != '0') return true;
        return false;
    }

    // Lock timer (timed lock): set / list / cancel. All server-side (toyUid only,
    // no BLE). While an active timing lock exists the server refuses unlockToy until
    // it expires or is cancelled.
    static void RunLockTimer(string base_url, string token, Device dev,
                             string sub, long val, string arg)
    {
        if (sub == "list")
        {
            JsonElement j = ApiPost(base_url,
                "api/feign/toyElectricTimingRecord/getAllToyUnlockTimingRecords",
                JsonObj(new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}), token);
            if ((j.GetProperty("state").GetString() ?? "") != "success")
                throw new Exception("getAllToyUnlockTimingRecords failed: " + j.GetRawText());
            if (!Has(j, "data")) { Console.WriteLine("[+] no outstanding lock timers"); return; }
            var arr = j.GetProperty("data");
            int count = 0;
            foreach (var r in arr.EnumerateArray()) { Console.WriteLine("    " + r.GetRawText()); count++; }
            if (count == 0) Console.WriteLine("[+] no outstanding lock timers");
            else Console.WriteLine("[+] " + count + " outstanding lock timer(s):" + Environment.NewLine);
            return;
        }
        if (sub == "status")
        {
            JsonElement d = ApiPost(base_url,
                "api/feign/toyUserBinding/getToyBindingInfoDetail",
                JsonObj(new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}), token);
            if ((d.GetProperty("state").GetString() ?? "") != "success")
                throw new Exception("getToyBindingInfoDetail failed: " + d.GetRawText());
            JsonElement b = d.TryGetProperty("data", out var dd) && dd.ValueKind == JsonValueKind.Object
                ? dd : default;
            string G(JsonElement el, string k)
            {
                if (el.ValueKind != JsonValueKind.Object || !el.TryGetProperty(k, out var v)) return "";
                return v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : v.GetRawText();
            }
            // timingTime = "d-h-m-s", counting down in real time; the
            // "timingTimeMillis" field is the same countdown in SECONDS.
            string tid2 = G(b, "timingId");
            string ttime = G(b, "timingTime");
            if (tid2.Length == 0 || ttime.Length == 0 || ttime == "0")
                Console.WriteLine("[+] no active lock timer");
            else
                Console.WriteLine("[+] active lock timer id=" + tid2
                    + " type=" + G(b, "timingType") + " remaining=" + ttime + " (d-h-m-s)");
            return;
        }
        if (sub == "set")
        {
            long mins = val;  // app picker: d*1440 + h*60 + m (minutes)
            if (mins < 1) throw new Exception("duration must be >= 1 min");
            JsonElement j = ApiPost(base_url,
                "api/feign/toyManualTimingRecord/saveManualTimingRecord",
                JsonObj(new Dictionary<string, object>
                {
                    { "timingTime", mins.ToString() },
                    { "toyUid", EncToyuid(dev.ToyId) },
                }), token);
            if ((j.GetProperty("state").GetString() ?? "") != "success")
                throw new Exception("saveManualTimingRecord failed: " + j.GetRawText());
            JsonElement d = j.GetProperty("data");
            long uid;
            if (d.ValueKind == JsonValueKind.Array && d.GetArrayLength() > 0)
                uid = d[0].GetProperty("uid").GetInt64();
            else if (d.ValueKind == JsonValueKind.Object && d.TryGetProperty("uid", out var u2))
                uid = u2.GetInt64();
            else
                throw new Exception("saveManualTimingRecord: no record uid in response: " + j.GetRawText());
            Console.WriteLine("[+] created timing record uid=" + uid);
            JsonElement u = ApiPost(base_url,
                "api/feign/toyUserBinding/toyUseTimingRecord",
                JsonObj(new Dictionary<string, object>
                {
                    { "timingUid", uid },
                    { "toyUid", EncToyuid(dev.ToyId) },
                    { "type", "1" },
                }), token);
            if ((u.GetProperty("state").GetString() ?? "") != "success")
                throw new Exception("toyUseTimingRecord failed: " + u.GetRawText());
            Console.WriteLine("[+] lock timer applied (" + mins + " min)");
            return;
        }
        if (sub == "cancel")
        {
            string tid, ttype;
            if (val >= 1)
            {
                tid = val.ToString();
                ttype = arg.Length == 0 ? "1" : arg;
            }
            else
            {
                // No explicit id: the app shows a single active timer whose
                // id/type come from getToyBindingInfoDetail.data.
                JsonElement d = ApiPost(base_url,
                    "api/feign/toyUserBinding/getToyBindingInfoDetail",
                    JsonObj(new Dictionary<string, object> {{ "toyUid", EncToyuid(dev.ToyId) }}), token);
                if ((d.GetProperty("state").GetString() ?? "") != "success")
                    throw new Exception("getToyBindingInfoDetail failed: " + d.GetRawText());
                JsonElement b = d.GetProperty("data");
                string G(JsonElement el, string k)
                {
                    if (!el.TryGetProperty(k, out var v)) return "";
                    return v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : v.GetRawText();
                }
                tid = G(b, "timingId");
                ttype = G(b, "timingType");
                if (tid.Length == 0) { Console.WriteLine("[+] no active lock timer to cancel"); return; }
                if (ttype.Length == 0) ttype = "1";
                Console.WriteLine("[*] active timer id=" + tid + " type=" + ttype);
            }
            JsonElement c = ApiPost(base_url,
                "api/feign/toyCancelTimingRecord/cancelTimingLock",
                JsonObj(new Dictionary<string, object>
                {
                    { "toyUid", EncToyuid(dev.ToyId) },
                    { "timingId", tid },
                    { "timingType", ttype },
                }), token);
            if ((c.GetProperty("state").GetString() ?? "") != "success")
                throw new Exception("cancelTimingLock failed: " + c.GetRawText());
            Console.WriteLine("[+] cancelled lock timer id=" + tid);
            return;
        }
        throw new Exception("unknown lock-timer subcommand '" + sub +
                            "' (use list | set <minutes> | cancel <timingId> [type])");
    }
}
