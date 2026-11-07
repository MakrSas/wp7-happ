using System;
using System.IO;
using System.IO.IsolatedStorage;

namespace HappWP
{
    /// <summary>Настройки приложения (IsolatedStorage) и кеш подписки.</summary>
    public static class AppSettings
    {
        const string SubFile = "subscription.txt";

        /// <summary>HWID, под которым HD7 уже зарегистрирован у провайдера как «HTC HD7 (WindowsPhone)».</summary>
        public const string DefaultHwid = "htchd7-simemu-0001";

        static IsolatedStorageSettings S { get { return IsolatedStorageSettings.ApplicationSettings; } }

        static T Get<T>(string k, T def)
        {
            T v;
            return S.TryGetValue(k, out v) ? v : def;
        }

        static void Set(string k, object v)
        {
            S[k] = v;
            S.Save();
        }

        public static string SubscriptionUrl { get { return Get("sub", ""); } set { Set("sub", value); } }
        public static string Hwid { get { return Get("hwid", DefaultHwid); } set { Set("hwid", value); } }
        public static string SelectedKey { get { return Get("sel", ""); } set { Set("sel", value); } }
        public static bool Connected { get { return Get("on", false); } set { Set("on", value); } }
        public static bool Daemon { get { return Get("daemon", true); } set { Set("daemon", value); } }
        public static bool AutoProxy { get { return Get("autoproxy", true); } set { Set("autoproxy", value); } }
        public static bool Mitm { get { return Get("mitm", true); } set { Set("mitm", value); } }
        public static int Port { get { return Get("port", 10809); } set { Set("port", value); } }
        public static DateTime Updated { get { return Get("updated", DateTime.MinValue); } set { Set("updated", value); } }

        public static string CachedSubscription
        {
            get
            {
                try
                {
                    using (var st = IsolatedStorageFile.GetUserStoreForApplication())
                    {
                        if (!st.FileExists(SubFile)) return null;
                        using (var r = new StreamReader(st.OpenFile(SubFile, FileMode.Open, FileAccess.Read)))
                            return r.ReadToEnd();
                    }
                }
                catch (Exception) { return null; }
            }
            set
            {
                try
                {
                    using (var st = IsolatedStorageFile.GetUserStoreForApplication())
                    using (var w = new StreamWriter(st.OpenFile(SubFile, FileMode.Create, FileAccess.Write)))
                        w.Write(value);
                }
                catch (Exception e) { Log.Error("кеш подписки", e); }
            }
        }
    }
}
