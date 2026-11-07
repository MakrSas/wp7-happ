using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HappWP
{
    /// <summary>Небольшой JSON-парсер: объект → Dictionary, массив → List, числа → double.</summary>
    public static class Json
    {
        public static object Parse(string s)
        {
            int i = 0;
            object v = Value(s, ref i);
            return v;
        }

        static void Ws(string s, ref int i)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        }

        static object Value(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("JSON оборвался");
            char c = s[i];
            if (c == '{') return Obj(s, ref i);
            if (c == '[') return Arr(s, ref i);
            if (c == '"') return Str(s, ref i);
            if (s.Length - i >= 4 && string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (s.Length - i >= 5 && string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (s.Length - i >= 4 && string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int st = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (st == i) throw new FormatException("JSON: неожиданный символ '" + c + "' в позиции " + i);
            return double.Parse(s.Substring(st, i - st), CultureInfo.InvariantCulture);
        }

        static Dictionary<string, object> Obj(string s, ref int i)
        {
            var d = new Dictionary<string, object>();
            i++;
            Ws(s, ref i);
            if (i < s.Length && s[i] == '}') { i++; return d; }
            for (;;)
            {
                Ws(s, ref i);
                string k = Str(s, ref i);
                Ws(s, ref i);
                if (i >= s.Length || s[i] != ':') throw new FormatException("JSON: нет ':'");
                i++;
                d[k] = Value(s, ref i);
                Ws(s, ref i);
                if (i < s.Length && s[i] == ',') { i++; continue; }
                if (i < s.Length && s[i] == '}') { i++; return d; }
                throw new FormatException("JSON: нет '}'");
            }
        }

        static List<object> Arr(string s, ref int i)
        {
            var l = new List<object>();
            i++;
            Ws(s, ref i);
            if (i < s.Length && s[i] == ']') { i++; return l; }
            for (;;)
            {
                l.Add(Value(s, ref i));
                Ws(s, ref i);
                if (i < s.Length && s[i] == ',') { i++; continue; }
                if (i < s.Length && s[i] == ']') { i++; return l; }
                throw new FormatException("JSON: нет ']'");
            }
        }

        static string Str(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("JSON: ожидалась строка");
            i++;
            var sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("JSON: строка не закрыта");
        }

        // ---------------------------------------------------------------- доступ по пути

        /// <summary>Get(o, "settings", "servers", 0, "address") — null, если чего-то нет.</summary>
        public static object Get(object o, params object[] path)
        {
            foreach (var p in path)
            {
                if (o == null) return null;
                if (p is string)
                {
                    var d = o as Dictionary<string, object>;
                    object v;
                    if (d == null || !d.TryGetValue((string)p, out v)) return null;
                    o = v;
                }
                else
                {
                    var l = o as List<object>;
                    int idx = (int)p;
                    if (l == null || idx >= l.Count) return null;
                    o = l[idx];
                }
            }
            return o;
        }

        public static string Str(object o, params object[] path)
        {
            var v = Get(o, path);
            if (v == null) return null;
            if (v is double) return ((double)v).ToString(CultureInfo.InvariantCulture);
            return v as string ?? v.ToString();
        }

        public static int Int(object o, int def, params object[] path)
        {
            var v = Get(o, path);
            if (v is double) return (int)(double)v;
            int r;
            return v is string && int.TryParse((string)v, out r) ? r : def;
        }

        public static bool Bool(object o, params object[] path)
        {
            var v = Get(o, path);
            return v is bool && (bool)v;
        }
    }
}
