using System;
using System.IO;
using System.IO.IsolatedStorage;
using System.Text;

namespace HappWP
{
    /// <summary>
    /// Журнал этапов запуска в IsolatedStorage. Отладчика нет, поэтому по последней строке прошлого
    /// запуска видно, где приложение умерло (в том числе в нативном коде, когда исключения нет).
    /// Журнал хранится на телефоне; на экране ошибки показывается весь текущий сеанс (Log.Session).
    /// </summary>
    public static class Log
    {
        const string FileName = "log.txt";
        const string PrevName = "log-prev.txt";
        public const string CleanExit = "== выход";

        static readonly StringBuilder session = new StringBuilder();

        /// <summary>Текст прошлого запуска (null, если его не было).</summary>
        public static string Previous { get; private set; }

        /// <summary>Прошлый запуск закончился не штатно.</summary>
        public static bool PreviousCrashed
        {
            get { return Previous != null && !Previous.TrimEnd().EndsWith(CleanExit); }
        }

        /// <summary>Последняя строка прошлого запуска.</summary>
        public static string PreviousLast
        {
            get
            {
                if (Previous == null) return null;
                var lines = Previous.TrimEnd().Split('\n');
                return lines[lines.Length - 1];
            }
        }

        public static void Start()
        {
            try
            {
                using (var store = IsolatedStorageFile.GetUserStoreForApplication())
                {
                    if (store.FileExists(FileName))
                    {
                        using (var r = new StreamReader(store.OpenFile(FileName, FileMode.Open, FileAccess.Read)))
                            Previous = r.ReadToEnd();
                        if (store.FileExists(PrevName)) store.DeleteFile(PrevName);
                        store.MoveFile(FileName, PrevName);
                    }
                }
            }
            catch (Exception) { }
            Write("== запуск, версия " + BuildInfo.Version);
        }

        public static void Write(string text)
        {
            string line = DateTime.Now.ToString("HH:mm:ss.fff") + " " + text;
            session.AppendLine(line);
            try
            {
                using (var store = IsolatedStorageFile.GetUserStoreForApplication())
                using (var s = store.OpenFile(FileName, FileMode.Append, FileAccess.Write))
                using (var w = new StreamWriter(s))
                    w.WriteLine(line);
            }
            catch (Exception) { }
        }

        public static void Error(string where, Exception e)
        {
            Write("!! " + where + ": " + Describe(e));
        }

        public static string Describe(Exception e)
        {
            var sb = new StringBuilder();
            for (int depth = 0; e != null && depth < 4; depth++, e = e.InnerException)
            {
                if (depth > 0) sb.Append("\n← ");
                sb.Append(e.GetType().FullName).Append(": ").Append(e.Message);
                if (e.StackTrace != null) sb.Append("\n").Append(e.StackTrace);
            }
            return sb.ToString();
        }

        public static string Session { get { return session.ToString(); } }
    }
}
