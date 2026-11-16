using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HappWP
{
    // Порядок методов = порядок в vtable (native/happ_native.c). Строки — BSTR (по умолчанию для COM).

    [ComImport, Guid("50A42CCA-ADB9-45FC-BEA2-7519D0F97933"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IHappNativeProbe
    {
        [PreserveSig] int GetVersion(out int version);
    }

    [ComImport, Guid("50A42CCA-ADB9-45FC-BEA2-7519D0F97933"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IHappNative
    {
        [PreserveSig] int GetVersion(out int version);
        [PreserveSig] int RegGetDword(string key, string name, out int value);
        [PreserveSig] int RegSetDword(string key, string name, int value);
        [PreserveSig] int RegGetString(string key, string name, out string value);
        [PreserveSig] int RegSetString(string key, string name, string value);
        [PreserveSig] int EngineStart(int allowDaemon, out int how);
        [PreserveSig] int EngineStop();
        [PreserveSig] int EngineStatus(out int writer);
        [PreserveSig] int Reload();
        [PreserveSig] int Ping(string host, int port, string sni, int insecure, out int ms, out string error);
        [PreserveSig] int HttpGet(string url, string headers, out int status, out string body);
        [PreserveSig] int Diag(out string text);
        [PreserveSig] int Post(string url, string text, out int status);
    }

    [ComImport, Guid("61A80CDD-2C09-41BC-8900-899346D9F3C8"), ClassInterface(ClassInterfaceType.None)]
    public class HappNativeClass
    {
        // Конструктор после сборки правит tools/fixcom.cs: «runtime managed internalcall», как у csc.
    }

    static class NativeProbe
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static object Create() { return new HappNativeClass(); }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Version(object o)
        {
            int v;
            int hr = ((IHappNativeProbe)o).GetVersion(out v);
            if (hr != 0) throw new InvalidOperationException("GetVersion = 0x" + hr.ToString("X8"));
            return v;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static object Full(object o) { return (IHappNative)o; }
    }

    /// <summary>Тип IHappNative упоминается только здесь: сбой его загрузки ловит фасад.</summary>
    static class NativeCalls
    {
        static IHappNative N(object o) { return (IHappNative)o; }

        public static int GetDword(object o, string k, string n, out int v) { return N(o).RegGetDword(k, n, out v); }
        public static int SetDword(object o, string k, string n, int v) { return N(o).RegSetDword(k, n, v); }
        public static int GetString(object o, string k, string n, out string v) { return N(o).RegGetString(k, n, out v); }
        public static int SetString(object o, string k, string n, string v) { return N(o).RegSetString(k, n, v); }
        public static int Start(object o, int allow, out int how) { return N(o).EngineStart(allow, out how); }
        public static int Stop(object o) { return N(o).EngineStop(); }
        public static int Status(object o, out int w) { return N(o).EngineStatus(out w); }
        public static int Reload(object o) { return N(o).Reload(); }
        public static int Ping(object o, string h, int p, string s, int i, out int ms, out string e) { return N(o).Ping(h, p, s, i, out ms, out e); }
        public static int Get(object o, string u, string h, out int st, out string b) { return N(o).HttpGet(u, h, out st, out b); }
        public static int Diag(object o, out string t) { return N(o).Diag(out t); }
        public static int Post(object o, string u, string t, out int st) { return N(o).Post(u, t, out st); }
    }

    /// <summary>Нативная часть. Никогда не бросает: при ошибке Available = false, причина в Error и в журнале.</summary>
    public static class Native
    {
        public const string CfgKey = @"Software\HappWP";
        public const string LiveKey = @"Software\HappWP\Live";
        public const int WriterNone = 0, WriterDaemon = 1, WriterThread = 2;

        static object obj;
        static bool full, tried;
        static readonly object gate = new object();

        public static string Error { get; private set; }
        public static int Version { get; private set; }

        public static bool Available
        {
            get
            {
                lock (gate)
                {
                    if (!tried)
                    {
                        tried = true;
                        Init();
                    }
                    return obj != null && full;
                }
            }
        }

        static void Init()
        {
            string last = Log.PreviousLast ?? "";
            if (Log.PreviousCrashed && last.Contains("native:") && !last.Contains("native: готово"))
            {
                Error = "пропущена: прошлый запуск упал на шаге «" + last.Substring(last.IndexOf("native:")) + "»";
                Log.Write("native: пропуск — " + Error);
                return;
            }
            string step = "";
            try
            {
                step = "загрузка Microsoft.Phone.InteropServices";
                Log.Write("native: " + step);
                var asm = Assembly.Load("Microsoft.Phone.InteropServices, Version=7.0.0.0, Culture=neutral, PublicKeyToken=24eec0d8c86cda1e");
                var type = asm.GetType("Microsoft.Phone.InteropServices.ComBridge", true);
                var m = type.GetMethod("RegisterComDll", new[] { typeof(string), typeof(Guid) });
                object r = m.Invoke(null, new object[] { "HappNative.dll", new Guid("61A80CDD-2C09-41BC-8900-899346D9F3C8") });
                if (r is int && (int)r != 0) throw new InvalidOperationException("RegisterComDll = 0x" + ((int)r).ToString("X8"));
                if (r is uint && (uint)r != 0) throw new InvalidOperationException("RegisterComDll = 0x" + ((uint)r).ToString("X8"));

                step = "создание COM-объекта";
                Log.Write("native: " + step);
                obj = NativeProbe.Create();
                step = "GetVersion";
                Version = NativeProbe.Version(obj);
                step = "полный интерфейс";
                NativeProbe.Full(obj);
                full = true;
                Log.Write("native: готово, версия " + Version);
            }
            catch (Exception e)
            {
                if (e is TargetInvocationException && e.InnerException != null) e = e.InnerException;
                Error = step + ": " + e.GetType().Name + ": " + e.Message;
                Log.Error("native, шаг «" + step + "»", e);
                full = false;
            }
        }

        static void Fail(string what, Exception e)
        {
            Error = what + ": " + e.GetType().Name + ": " + e.Message;
            Log.Error("native " + what, e);
            full = false;
        }

        public static int GetDword(string key, string name, int def)
        {
            if (!Available) return def;
            try { int v; return NativeCalls.GetDword(obj, key, name, out v) == 0 ? v : def; }
            catch (Exception e) { Fail("RegGetDword", e); return def; }
        }

        public static void SetDword(string key, string name, int value)
        {
            if (!Available) return;
            try { NativeCalls.SetDword(obj, key, name, value); }
            catch (Exception e) { Fail("RegSetDword", e); }
        }

        public static string GetString(string key, string name)
        {
            if (!Available) return null;
            try { string v; return NativeCalls.GetString(obj, key, name, out v) == 0 ? v : null; }
            catch (Exception e) { Fail("RegGetString", e); return null; }
        }

        public static void SetString(string key, string name, string value)
        {
            if (!Available) return;
            try { NativeCalls.SetString(obj, key, name, value ?? ""); }
            catch (Exception e) { Fail("RegSetString", e); }
        }

        public static int Start(bool allowDaemon)
        {
            if (!Available) return -1;
            try { int how; NativeCalls.Start(obj, allowDaemon ? 1 : 0, out how); return how; }
            catch (Exception e) { Fail("EngineStart", e); return -1; }
        }

        public static void Stop()
        {
            if (!Available) return;
            try { NativeCalls.Stop(obj); }
            catch (Exception e) { Fail("EngineStop", e); }
        }

        public static int Status()
        {
            if (!Available) return WriterNone;
            try { int w; NativeCalls.Status(obj, out w); return w; }
            catch (Exception e) { Fail("EngineStatus", e); return WriterNone; }
        }

        public static void Reload()
        {
            if (!Available) return;
            try { NativeCalls.Reload(obj); }
            catch (Exception e) { Fail("Reload", e); }
        }

        /// <summary>TCP + TLS до сервера, мс; -1 и error при ошибке. Блокирует — вызывать из фонового потока.</summary>
        public static int Ping(string host, int port, string sni, bool insecure, out string error)
        {
            error = null;
            if (!Available) { error = Error; return -1; }
            try { int ms; NativeCalls.Ping(obj, host, port, sni ?? "", insecure ? 1 : 0, out ms, out error); return ms; }
            catch (Exception e) { error = e.Message; return -1; }
        }

        /// <summary>Проверка цепочки: движок, журнал happd, запрос через прокси и напрямую через Trojan. Блокирует.</summary>
        public static string Diag()
        {
            if (!Available) return "нативная часть недоступна: " + Error;
            try { string t; NativeCalls.Diag(obj, out t); return t; }
            catch (Exception e) { return e.Message; }
        }

        /// <summary>Готова ли нативная часть, не пытаясь её загрузить (для журнала).</summary>
        public static bool Ready { get { return tried && obj != null && full; } }

        /// <summary>POST по http:// своим сокетом, мимо прокси Wi-Fi. Блокирует.</summary>
        public static int Post(string url, string text)
        {
            if (!Ready) return -1;
            try { int st; NativeCalls.Post(obj, url, text, out st); return st; }
            catch (Exception) { return -1; }
        }

        /// <summary>HTTPS GET со своими заголовками. status -1 — ошибка (текст в body). Блокирует.</summary>
        public static string HttpGet(string url, string headers, out int status)
        {
            status = -1;
            if (!Available) return Error;
            try { string body; NativeCalls.Get(obj, url, headers ?? "", out status, out body); return body; }
            catch (Exception e) { return e.Message; }
        }
    }
}
