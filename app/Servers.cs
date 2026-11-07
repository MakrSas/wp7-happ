using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace HappWP
{
    /// <summary>Сервер из подписки.</summary>
    public sealed class Server : INotifyPropertyChanged
    {
        public string Name { get; set; }
        public string Country { get; set; }      // «SE» из флага в названии
        public string Group { get; set; }        // раздел подписки («ОБЫЧНЫЕ», «Свежие резервы»…)
        /// <summary>У первого сервера раздела — название раздела (строчными, как заголовки групп в WP7).</summary>
        public string GroupHeader { get; set; }
        public string Protocol { get; set; }     // trojan / vless / hysteria…
        public string Network { get; set; }      // tcp / grpc / ws…
        public string Security { get; set; }     // tls / reality / none
        public string Host { get; set; }
        public int Port { get; set; }
        public string Secret { get; set; }       // пароль Trojan или UUID VLESS
        public string Sni { get; set; }
        public bool Insecure { get; set; }

        /// <summary>Что умеет happd: пока только Trojan поверх TCP + TLS.</summary>
        public bool Supported
        {
            get { return Protocol == "trojan" && (Network ?? "tcp") == "tcp" && Security == "tls"; }
        }

        public string Kind
        {
            get
            {
                string k = Protocol + (Network != null && Network != "tcp" ? "/" + Network : "") +
                           (Security == "reality" ? " reality" : "");
                return Supported ? k : k + " — пока не поддерживается";
            }
        }

        int ping = int.MinValue;
        string pingError;

        /// <summary>int.MinValue — не проверяли, -1 — ошибка.</summary>
        public int Ping
        {
            get { return ping; }
            set { ping = value; Changed("Ping"); Changed("Subtitle"); Changed("PingText"); }
        }

        public string PingError
        {
            get { return pingError; }
            set { pingError = value; Changed("Subtitle"); }
        }

        public string PingText
        {
            get { return ping == int.MinValue ? "" : ping < 0 ? "нет связи" : ping + " мс"; }
        }

        public string Subtitle
        {
            get
            {
                var sb = new StringBuilder();
                if (!string.IsNullOrEmpty(Country)) sb.Append(Country).Append(" · ");
                sb.Append(Kind);
                if (PingText.Length > 0) sb.Append(" · ").Append(PingText);
                return sb.ToString();
            }
        }

        bool selected;
        public bool Selected
        {
            get { return selected; }
            set { selected = value; Changed("Selected"); Changed("TitleOpacity"); }
        }

        public double TitleOpacity { get { return Supported ? 1.0 : 0.45; } }

        /// <summary>Ключ для запоминания выбора между обновлениями подписки.</summary>
        public string Key { get { return Protocol + "|" + Host + "|" + Port + "|" + Name; } }

        public event PropertyChangedEventHandler PropertyChanged;

        void Changed(string p)
        {
            var h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(p));
        }
    }

    public static class Subscription
    {
        /// <summary>
        /// Заголовки как у Happ: без x-hwid панель (Remnawave) отдаёт заглушку «App not supported».
        /// HWID — тот, под которым телефон уже зарегистрирован у провайдера как «HTC HD7».
        /// </summary>
        public static string Headers(string hwid)
        {
            return "User-Agent: Happ/3.5.0\r\n" +
                   "x-hwid: " + hwid + "\r\n" +
                   "x-device-os: WindowsPhone\r\n" +
                   "x-ver-os: 7.8\r\n" +
                   "x-device-model: HTC HD7\r\n";
        }

        /// <summary>Разобрать ответ подписки: JSON-конфиги Xray или список ссылок (возможно, в base64).</summary>
        public static List<Server> Parse(string body)
        {
            body = (body ?? "").Trim();
            if (body.StartsWith("[") || body.StartsWith("{")) return ParseJson(body);
            if (body.IndexOf("://") < 0)
            {
                try { var b = FromBase64(body); body = Encoding.UTF8.GetString(b, 0, b.Length); }
                catch (FormatException) { }
            }
            var list = new List<Server>();
            string group = null;
            foreach (var raw in body.Split('\n'))
            {
                var s = ParseLink(raw.Trim());
                if (s == null) continue;
                if (IsHeader(s.Name)) { group = Clean(s.Name); continue; }
                s.Group = group;
                list.Add(s);
            }
            return list;
        }

        static List<Server> ParseJson(string body)
        {
            var list = new List<Server>();
            object root = Json.Parse(body);
            var cfgs = root as List<object> ?? new List<object> { root };
            string group = null;
            foreach (var cfg in cfgs)
            {
                string remarks = Json.Str(cfg, "remarks") ?? "";
                var outs = Json.Get(cfg, "outbounds") as List<object>;
                if (outs == null) continue;
                foreach (var o in outs)
                {
                    string proto = Json.Str(o, "protocol");
                    if (proto == null || proto == "freedom" || proto == "blackhole" || proto == "dns") continue;
                    var s = new Server
                    {
                        Protocol = proto,
                        Network = Json.Str(o, "streamSettings", "network") ?? "tcp",
                        Security = Json.Str(o, "streamSettings", "security") ?? "none",
                    };
                    if (proto == "trojan" || proto == "shadowsocks")
                    {
                        s.Host = Json.Str(o, "settings", "servers", 0, "address");
                        s.Port = Json.Int(o, 0, "settings", "servers", 0, "port");
                        s.Secret = Json.Str(o, "settings", "servers", 0, "password");
                    }
                    else
                    {
                        s.Host = Json.Str(o, "settings", "vnext", 0, "address");
                        s.Port = Json.Int(o, 0, "settings", "vnext", 0, "port");
                        s.Secret = Json.Str(o, "settings", "vnext", 0, "users", 0, "id");
                    }
                    s.Sni = Json.Str(o, "streamSettings", "tlsSettings", "serverName") ??
                            Json.Str(o, "streamSettings", "realitySettings", "serverName");
                    s.Insecure = Json.Bool(o, "streamSettings", "tlsSettings", "allowInsecure");
                    s.Name = remarks;
                    if (IsHeader(remarks)) { group = Clean(remarks); break; }
                    Finish(s);
                    s.Group = group;
                    if (s.Host != null) list.Add(s);
                    break; // один прокси на конфиг: остальные outbound — служебные
                }
            }
            return list;
        }

        /// <summary>trojan://пароль@хост:порт?sni=…&amp;type=tcp&amp;security=tls#Имя (и похожие vless://).</summary>
        static Server ParseLink(string link)
        {
            int p = link.IndexOf("://");
            if (p <= 0) return null;
            string scheme = link.Substring(0, p).ToLowerInvariant();
            if (scheme != "trojan" && scheme != "vless") return null;
            string rest = link.Substring(p + 3), name = "";
            int hash = rest.IndexOf('#');
            if (hash >= 0) { name = Uri.UnescapeDataString(rest.Substring(hash + 1)); rest = rest.Substring(0, hash); }
            string query = "";
            int q = rest.IndexOf('?');
            if (q >= 0) { query = rest.Substring(q + 1); rest = rest.Substring(0, q); }
            int at = rest.LastIndexOf('@');
            if (at < 0) return null;
            string secret = Uri.UnescapeDataString(rest.Substring(0, at)), hostport = rest.Substring(at + 1).TrimEnd('/');
            int colon = hostport.LastIndexOf(':');
            if (colon < 0) return null;
            var args = new Dictionary<string, string>();
            foreach (var kv in query.Split('&'))
            {
                int e = kv.IndexOf('=');
                if (e > 0) args[kv.Substring(0, e)] = Uri.UnescapeDataString(kv.Substring(e + 1));
            }
            string v;
            var s = new Server
            {
                Protocol = scheme,
                Name = name,
                Host = hostport.Substring(0, colon).Trim('[', ']'),
                Port = int.Parse(hostport.Substring(colon + 1)),
                Secret = secret,
                Network = args.TryGetValue("type", out v) ? v : "tcp",
                Security = args.TryGetValue("security", out v) ? v : (scheme == "trojan" ? "tls" : "none"),
                Sni = args.TryGetValue("sni", out v) ? v : null,
                Insecure = args.TryGetValue("allowInsecure", out v) && (v == "1" || v == "true"),
            };
            Finish(s);
            return s;
        }

        static void Finish(Server s)
        {
            s.Country = Flag(s.Name);
            s.Name = Clean(s.Name);
            if (s.Name.Length == 0) s.Name = s.Host;
        }

        /// <summary>«🔻ОБЫЧНЫЕ (НЕ обходы)🔻» — это не сервер, а заголовок раздела.</summary>
        static bool IsHeader(string name)
        {
            return name != null && name.IndexOf("\U0001F53B", StringComparison.Ordinal) >= 0;
        }

        /// <summary>Флаг 🇸🇪 → «SE» (два символа regional indicator).</summary>
        static string Flag(string name)
        {
            if (name == null) return null;
            for (int i = 0; i + 3 < name.Length; i++)
            {
                if (name[i] == '\uD83C' && name[i + 1] >= '\uDDE6' && name[i + 1] <= '\uDDFF' &&
                    name[i + 2] == '\uD83C' && name[i + 3] >= '\uDDE6' && name[i + 3] <= '\uDDFF')
                {
                    return new string(new[] { (char)('A' + name[i + 1] - '\uDDE6'), (char)('A' + name[i + 3] - '\uDDE6') });
                }
            }
            return null;
        }

        /// <summary>Шрифт WP7 не рисует эмодзи: убираем суррогатные пары, ⚡ и прочие значки.</summary>
        public static string Clean(string name)
        {
            if (name == null) return "";
            var sb = new StringBuilder();
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (c >= '\uD800' && c <= '\uDBFF') { i++; continue; }
                if (c == '️' || c == '‍' || (c >= '☀' && c <= '➿') || (c >= '←' && c <= '⇿')) continue;
                sb.Append(c);
            }
            string s = sb.ToString().Trim();
            while (s.Contains("  ")) s = s.Replace("  ", " ");
            return s.Trim(' ', '|', '-');
        }

        static byte[] FromBase64(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/').Replace("\r", "").Replace("\n", "");
            while (s.Length % 4 != 0) s += "=";
            return Convert.FromBase64String(s);
        }
    }
}
