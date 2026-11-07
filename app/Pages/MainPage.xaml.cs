using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;

namespace HappWP
{
    public partial class MainPage : PhoneApplicationPage
    {
        readonly ObservableCollection<Server> servers = new ObservableCollection<Server>();
        readonly DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        Server selected;
        bool loading, busy, idleDisabled;

        public MainPage()
        {
            Log.Write("MainPage: XAML");
            InitializeComponent();
            Log.Write("MainPage: XAML загружен");
            AboutText.Text = string.Format(AboutText.Text, BuildInfo.Version);
            ServerList.ItemsSource = servers;

            loading = true;
            SubBox.Text = AppSettings.SubscriptionUrl;
            PortBox.Text = AppSettings.Port.ToString();
            HwidBox.Text = AppSettings.Hwid;
            DaemonSwitch.IsChecked = AppSettings.Daemon;
            MitmSwitch.IsChecked = AppSettings.Mitm;
            AutoProxySwitch.IsChecked = AppSettings.AutoProxy;
            VpnSwitch.IsChecked = AppSettings.Connected;
            loading = false;

            Switch(VpnSwitch, () => AppSettings.Connected, v => { AppSettings.Connected = v; ApplyVpn(); });
            Switch(DaemonSwitch, () => AppSettings.Daemon, v => { AppSettings.Daemon = v; if (AppSettings.Connected) RestartEngine(); });
            Switch(AutoProxySwitch, () => AppSettings.AutoProxy, v =>
            {
                AppSettings.AutoProxy = v;
                Native.SetDword(Native.CfgKey, "AutoProxy", v ? 1 : 0);
            });
            Switch(MitmSwitch, () => AppSettings.Mitm, v =>
            {
                AppSettings.Mitm = v;
                Native.SetDword(Native.CfgKey, "Mitm", v ? 1 : 0);
                Native.Reload();
            });
            CertButton.Click += (o, e) =>
            {
                if (!AppSettings.Connected)
                {
                    MessageBox.Show("Сначала включите VPN и прокси в настройках Wi-Fi: страница сертификата открывается через Happ.", "сертификат", MessageBoxButton.OK);
                    return;
                }
                // Адрес самого телефона: однословные имена IE считает локальными и шлёт мимо прокси.
                string page = !string.IsNullOrEmpty(localIp)
                    ? "http://" + localIp + ":" + AppSettings.Port + "/"
                    : "http://happ.cert/";
                Log.Write("сертификат: открываю " + page);
                new Microsoft.Phone.Tasks.WebBrowserTask { Uri = new Uri(page) }.Show();
            };

            ServerList.SelectionChanged += (o, e) =>
            {
                var s = ServerList.SelectedItem as Server;
                ServerList.SelectedItem = null;
                if (s != null) Select(s, true);
            };
            ServerBox.Tap += (o, e) => MainPivot.SelectedIndex = 1;
            UpdateButton.Click += (o, e) => UpdateSubscription();
            DiagButton.Click += (o, e) => RunDiag();
            SubBox.LostFocus += (o, e) => AppSettings.SubscriptionUrl = SubBox.Text.Trim();
            HwidBox.LostFocus += (o, e) =>
            {
                string v = HwidBox.Text.Trim();
                AppSettings.Hwid = v.Length > 0 ? v : AppSettings.DefaultHwid;
            };
            PortBox.LostFocus += (o, e) =>
            {
                int p;
                if (int.TryParse(PortBox.Text, out p) && p > 1024 && p < 65536 && p != AppSettings.Port)
                {
                    AppSettings.Port = p;
                    if (AppSettings.Connected) RestartEngine();
                }
                PortBox.Text = AppSettings.Port.ToString();
                UpdateProxyText();
            };
            KeyEventHandler enter = (o, e) => { if (e.Key == Key.Enter) Focus(); };
            SubBox.KeyUp += enter;
            PortBox.KeyUp += enter;
            HwidBox.KeyUp += enter;

            LoadServers(AppSettings.CachedSubscription, false);
            UpdateProxyText();
            Log.Write("MainPage: готово, серверов " + servers.Count);

            timer.Tick += (o, e) => Refresh();
            Loaded += (o, e) =>
            {
                Log.Write("MainPage: показана");
                NativeText.Text = Native.Available ? "нативная часть: версия " + Native.Version : "нативная часть недоступна — " + Native.Error;
                if (AppSettings.Connected) ApplyVpn();
                Refresh();
                timer.Start();
            };
            Unloaded += (o, e) => timer.Stop();
        }

        /// <summary>«Вкл / Выкл» по-русски и без ложных событий при первой отрисовке (как в SIM-эмуляторе).</summary>
        void Switch(ToggleSwitch t, Func<bool> get, Action<bool> set)
        {
            t.Content = t.IsChecked == true ? "Вкл" : "Выкл";
            EventHandler<RoutedEventArgs> h = (o, e) =>
            {
                bool v = t.IsChecked == true;
                t.Content = v ? "Вкл" : "Выкл";
                if (loading || v == get()) return;
                set(v);
            };
            t.Checked += h;
            t.Unchecked += h;
        }

        // ------------------------------------------------------------ серверы

        void LoadServers(string body, bool fresh)
        {
            if (string.IsNullOrEmpty(body)) { EmptyText.Visibility = Visibility.Visible; return; }
            List<Server> list;
            try { list = Subscription.Parse(body); }
            catch (Exception e)
            {
                Log.Error("разбор подписки", e);
                SubStatus.Text = "не удалось разобрать подписку: " + e.Message;
                return;
            }
            servers.Clear();
            string group = null;
            foreach (var s in list)
            {
                if (s.Group != group) { group = s.Group; s.GroupHeader = (group ?? "").ToLowerInvariant(); }
                servers.Add(s);
            }
            EmptyText.Visibility = servers.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            int ok = servers.Count(x => x.Supported);
            SubStatus.Text = "серверов: " + servers.Count + ", из них работают в этой версии: " + ok +
                             (AppSettings.Updated != DateTime.MinValue ? "\nобновлено " + AppSettings.Updated.ToString("d MMM, HH:mm") : "");

            var prev = servers.FirstOrDefault(x => x.Key == AppSettings.SelectedKey && x.Supported);
            if (prev == null && fresh) prev = servers.FirstOrDefault(x => x.Supported);
            if (prev != null) Select(prev, false);
        }

        void Select(Server s, bool user)
        {
            if (!s.Supported)
            {
                if (user) MessageBox.Show(s.Kind + ".\n\nВ этой версии работают только серверы Trojan.", s.Name, MessageBoxButton.OK);
                return;
            }
            if (selected != null) selected.Selected = false;
            selected = s;
            s.Selected = true;
            AppSettings.SelectedKey = s.Key;
            ServerName.Text = s.Name;
            ServerInfo.Text = s.Subtitle;
            Log.Write("сервер: " + s.Name);
            if (AppSettings.Connected) { PushServer(); Native.Reload(); }
            if (user) MainPivot.SelectedIndex = 0;
        }

        // ------------------------------------------------------------ подписка

        void Update_Click(object sender, EventArgs e) { UpdateSubscription(); }

        void UpdateSubscription()
        {
            string url = SubBox.Text.Trim();
            AppSettings.SubscriptionUrl = url;
            if (url.Length == 0)
            {
                MainPivot.SelectedIndex = 2;
                SubStatus.Text = "вставьте ссылку на подписку";
                return;
            }
            if (busy) return;
            busy = true;
            SubStatus.Text = "загружаю подписку…";
            Progress(true, "загрузка подписки");
            string headers = Subscription.Headers(AppSettings.Hwid);
            new Thread(() =>
            {
                int status;
                string body = Native.HttpGet(url, headers, out status);
                Dispatcher.BeginInvoke(() =>
                {
                    busy = false;
                    Progress(false, null);
                    Log.Write("подписка: HTTP " + status + ", " + (body ?? "").Length + " символов");
                    if (status != 200)
                    {
                        SubStatus.Text = status < 0 ? "ошибка: " + body : "сервер ответил " + status;
                        return;
                    }
                    AppSettings.CachedSubscription = body;
                    AppSettings.Updated = DateTime.Now;
                    LoadServers(body, true);
                    PingAll();
                });
            }).Start();
        }

        // ------------------------------------------------------------ проверка

        void RunDiag()
        {
            if (busy) return;
            busy = true;
            DiagText.Visibility = Visibility.Visible;
            DiagText.Text = "проверяю…";
            Progress(true, "проверка");
            new Thread(() =>
            {
                string r = Native.Diag();
                Dispatcher.BeginInvoke(() =>
                {
                    busy = false;
                    Progress(false, null);
                    DiagText.Text = r;
                    Log.Write("проверка:\n" + r);
                });
            }).Start();
        }

        // ------------------------------------------------------------ пинг

        void Ping_Click(object sender, EventArgs e) { PingAll(); }

        void PingAll()
        {
            if (busy) return;
            var list = servers.Where(s => s.Supported).ToList();
            if (list.Count == 0) return;
            busy = true;
            Progress(true, "проверка серверов");
            foreach (var s in list) s.Ping = int.MinValue;
            new Thread(() =>
            {
                foreach (var s in list)
                {
                    string err;
                    int ms = Native.Ping(s.Host, s.Port, s.Sni, s.Insecure, out err);
                    var srv = s;
                    Dispatcher.BeginInvoke(() =>
                    {
                        srv.Ping = ms;
                        srv.PingError = err;
                        if (srv == selected) ServerInfo.Text = srv.Subtitle;
                    });
                }
                Dispatcher.BeginInvoke(() => { busy = false; Progress(false, null); });
            }).Start();
        }

        void Progress(bool on, string text)
        {
            if (SystemTray.ProgressIndicator == null) SystemTray.ProgressIndicator = new ProgressIndicator();
            SystemTray.ProgressIndicator.IsIndeterminate = on;
            SystemTray.ProgressIndicator.IsVisible = on;
            SystemTray.ProgressIndicator.Text = text;
        }

        // ------------------------------------------------------------ VPN

        void PushServer()
        {
            if (selected == null) return;
            string k = Native.CfgKey;
            Native.SetDword(k, "Type", 1);
            Native.SetString(k, "Server", selected.Host);
            Native.SetDword(k, "Port", selected.Port);
            Native.SetString(k, "Password", selected.Secret);
            Native.SetString(k, "Sni", selected.Sni ?? "");
            Native.SetDword(k, "Insecure", selected.Insecure ? 1 : 0);
            Native.SetDword(k, "ListenPort", AppSettings.Port);
            Native.SetDword(k, "Mitm", AppSettings.Mitm ? 1 : 0);
            Native.SetDword(k, "AutoProxy", AppSettings.AutoProxy ? 1 : 0);
        }

        void ApplyVpn()
        {
            if (!Native.Available) return;
            if (AppSettings.Connected)
            {
                if (selected == null)
                {
                    MainPivot.SelectedIndex = 1;
                    return;
                }
                PushServer();
                Native.SetDword(Native.CfgKey, "Enabled", 1);
                Log.Write("native: запуск движка, фон=" + AppSettings.Daemon);
                int how = Native.Start(AppSettings.Daemon);
                Log.Write("native: готово, движок " + how);
                if (how == Native.WriterThread && !idleDisabled)
                {
                    // Поток живёт, пока жив процесс приложения: не даём ему уснуть под экраном блокировки.
                    try
                    {
                        PhoneApplicationService.Current.ApplicationIdleDetectionMode = IdleDetectionMode.Disabled;
                        idleDisabled = true;
                    }
                    catch (InvalidOperationException) { }
                }
            }
            else
            {
                Native.SetDword(Native.CfgKey, "Enabled", 0);
                Native.Stop();
            }
            Refresh();
        }

        void RestartEngine()
        {
            Native.Stop();
            ApplyVpn();
        }

        // ------------------------------------------------------------ состояние

        string localIp;

        int proxyNets;

        void UpdateProxyText()
        {
            string manual = "Настройки → Wi-Fi → ваша сеть → прокси: вкл, сервер " +
                            (string.IsNullOrEmpty(localIp) ? "(адрес появится после включения VPN)" : localIp) +
                            ", порт " + AppSettings.Port;
            if (AppSettings.AutoProxy && proxyNets > 0)
                ProxyText.Text = "Happ сам включает прокси в запомненных сетях: " + proxyNets +
                                 ". Для новой сети один раз: " + manual.Substring(manual.IndexOf("Wi-Fi"));
            else
                ProxyText.Text = manual + (AppSettings.AutoProxy ? ". Дальше Happ будет делать это сам." : "");
        }

        static string Size(int kb)
        {
            if (kb < 1024) return kb + " КБ";
            return (kb / 1024.0).ToString(kb < 10240 ? "0.0" : "0") + " МБ";
        }

        void Refresh()
        {
            int writer = Native.Status();
            bool on = AppSettings.Connected;
            bool running = writer != Native.WriterNone;
            string err = running ? Native.GetString(Native.LiveKey, "Error") : null;

            if (!on)
            {
                StateText.Text = "отключено";
                StateText.Foreground = (Brush)Application.Current.Resources["PhoneForegroundBrush"];
                StateHint.Text = selected == null ? "выберите сервер и включите VPN" : "включите VPN";
            }
            else if (!Native.Available)
            {
                StateText.Text = "нет доступа";
                StateHint.Text = "нативная часть недоступна: " + Native.Error;
            }
            else if (!running)
            {
                StateText.Text = "подключаюсь…";
                StateHint.Text = "запускаю прокси";
            }
            else
            {
                StateText.Text = "подключено";
                StateText.Foreground = (Brush)Application.Current.Resources["PhoneAccentBrush"];
                StateHint.Text = (writer == Native.WriterDaemon ? "работает в фоне" : "работает, пока открыто приложение") +
                                 " · прокси " + (localIp ?? "…") + ":" + AppSettings.Port;
            }

            if (running)
            {
                string ip = Native.GetString(Native.LiveKey, "LocalIp");
                int nets = Native.GetDword(Native.LiveKey, "ProxyNets", 0);
                if ((!string.IsNullOrEmpty(ip) && ip != localIp) || nets != proxyNets)
                {
                    if (!string.IsNullOrEmpty(ip)) localIp = ip;
                    proxyNets = nets;
                    UpdateProxyText();
                }
                int up = Native.GetDword(Native.LiveKey, "UpKB", 0), down = Native.GetDword(Native.LiveKey, "DownKB", 0);
                int conns = Native.GetDword(Native.LiveKey, "Conns", 0);
                TrafficText.Text = "↑ " + Size(up) + "   ↓ " + Size(down) + "   соединений: " + conns;
                CertStatus.Text = Native.GetDword(Native.LiveKey, "CaReady", 0) == 1
                    ? "сертификат готов — откроется в Internet Explorer"
                    : "сертификат создаётся на телефоне, это до минуты…";
            }
            else
            {
                TrafficText.Text = "—";
            }
            ErrorText.Text = string.IsNullOrEmpty(err) ? "" : "последняя ошибка: " + err;
            ErrorText.Visibility = string.IsNullOrEmpty(err) ? Visibility.Collapsed : Visibility.Visible;
        }
    }
}
