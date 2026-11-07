using System;
using System.IO;
using System.IO.IsolatedStorage;
using System.Net;
using System.Text;

namespace HappWP
{
    /// <summary>
    /// Журнал этапов запуска в IsolatedStorage. Отладчика нет, поэтому по последней строке прошлого
    /// запуска видно, где приложение умерло (в том числе в нативном коде, когда исключения нет).
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
            if (Previous != null) Upload("---- прошлый запуск ----\n" + Previous + "---- конец ----");
            Write("== запуск, версия " + BuildInfo.Version);
            SendPending();
        }

        /// <summary>Сервер на маке (tools/serve.py): туда уходит каждая строка журнала.</summary>
        public const string Server = "http://192.168.0.103:8766/log?app=happ";

        /// <summary>Отправить текст на мак. Асинхронно и без ошибок: сети может не быть.</summary>
        static readonly System.Collections.Generic.Queue<string> outbox = new System.Collections.Generic.Queue<string>();
        static bool sending;

        /// <summary>
        /// Отправить текст на мак. Пока нативная часть не готова — копим. Потом шлём своим сокетом:
        /// системный HTTP идёт через прокси Wi-Fi, а прокси — это мы сами, и при ошибке журнал бы не дошёл.
        /// </summary>
        public static void Upload(string text)
        {
#if RELEASE
            return;
#endif
            lock (outbox)
            {
                if (outbox.Count < 500) outbox.Enqueue(text);
                if (sending) return;
                sending = true;
            }
            System.Threading.ThreadPool.QueueUserWorkItem(_ => Pump());
        }

        static void Pump()
        {
            for (;;)
            {
                string text;
                lock (outbox)
                {
                    if (outbox.Count == 0 || !Native.Ready) { sending = false; return; }
                    text = outbox.Peek();
                }
                if (Native.Post(Server + "&t=" + DateTime.Now.Ticks, text) < 0) { lock (outbox) sending = false; return; }
                lock (outbox) outbox.Dequeue();
            }
        }

        /// <summary>Нативная часть загрузилась — отправить накопленное.</summary>
        public static void Flush()
        {
            lock (outbox)
            {
                if (sending || outbox.Count == 0) return;
                sending = true;
            }
            System.Threading.ThreadPool.QueueUserWorkItem(_ => Pump());
        }

        const string PendingName = "pending-upload.txt";

        /// <summary>
        /// Большой отчёт: сначала в файл, потом на мак. Файл удаляется только после ответа сервера,
        /// так что если приложение закроют посреди отправки, отчёт уйдёт при следующем запуске.
        /// </summary>
        public static void UploadReliable(string text)
        {
            try
            {
                using (var store = IsolatedStorageFile.GetUserStoreForApplication())
                using (var w = new StreamWriter(store.OpenFile(PendingName, FileMode.Create, FileAccess.Write)))
                    w.Write(text);
            }
            catch (Exception) { }
            SendPending();
        }

        public static void SendPending()
        {
#if RELEASE
            return;
#endif
            string text;
            try
            {
                using (var store = IsolatedStorageFile.GetUserStoreForApplication())
                {
                    if (!store.FileExists(PendingName)) return;
                    using (var r = new StreamReader(store.OpenFile(PendingName, FileMode.Open, FileAccess.Read)))
                        text = r.ReadToEnd();
                }
            }
            catch (Exception) { return; }
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(new Uri(Server + "&t=" + DateTime.Now.Ticks));
                req.Method = "POST";
                req.ContentType = "text/plain; charset=utf-8";
                byte[] body = Encoding.UTF8.GetBytes(text);
                req.BeginGetRequestStream(ar =>
                {
                    try
                    {
                        using (var s = req.EndGetRequestStream(ar)) s.Write(body, 0, body.Length);
                        req.BeginGetResponse(ar2 =>
                        {
                            try
                            {
                                req.EndGetResponse(ar2).Close();
                                using (var store = IsolatedStorageFile.GetUserStoreForApplication())
                                    if (store.FileExists(PendingName)) store.DeleteFile(PendingName);
                                Upload(DateTime.Now.ToString("HH:mm:ss.fff") + " отчёт доставлен, " + body.Length + " байт");
                            }
                            catch (Exception) { }
                        }, null);
                    }
                    catch (Exception) { }
                }, null);
            }
            catch (Exception) { }
        }

        public static void Write(string text)
        {
            string line = DateTime.Now.ToString("HH:mm:ss.fff") + " " + text;
            session.AppendLine(line);
            Upload(line);
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
