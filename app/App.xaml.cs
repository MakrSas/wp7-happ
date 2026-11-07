using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;

namespace HappWP
{
    public partial class App : Application
    {
        public PhoneApplicationFrame RootFrame { get; private set; }

        bool initialized, showingError;

        public App()
        {
            Log.Start();
            UnhandledException += OnUnhandledException;
            try
            {
                InitializeComponent();
                Log.Write("App.xaml загружен");
            }
            catch (Exception e)
            {
                // Без App.xaml пропадут только наши стили — страницы всё равно попробуем открыть.
                Log.Error("App.xaml", e);
            }
            InitializePhoneApplication();
        }

        void Application_Launching(object sender, LaunchingEventArgs e) { Log.Write("Launching"); }
        void Application_Activated(object sender, ActivatedEventArgs e) { Log.Write("Activated"); }
        void Application_Deactivated(object sender, DeactivatedEventArgs e) { Log.Write("Deactivated"); }
        void Application_Closing(object sender, ClosingEventArgs e) { Log.Write(Log.CleanExit); }

        void OnUnhandledException(object sender, ApplicationUnhandledExceptionEventArgs e)
        {
            Log.Error("необработанное исключение", e.ExceptionObject);
            e.Handled = true;
            ShowError("необработанное исключение", e.ExceptionObject);
        }

        void InitializePhoneApplication()
        {
            if (initialized) return;
            RootFrame = new PhoneApplicationFrame();
            RootFrame.Navigated += CompleteInitializePhoneApplication;
            RootFrame.NavigationFailed += (s, e) =>
            {
                Log.Error("навигация " + e.Uri, e.Exception);
                e.Handled = true;
                ShowError("не открылась страница " + e.Uri, e.Exception);
            };
            initialized = true;
            Log.Write("кадр создан");
        }

        void CompleteInitializePhoneApplication(object sender, NavigationEventArgs e)
        {
            Log.Write("открыта " + e.Uri);
            if (RootVisual != RootFrame && !showingError) RootVisual = RootFrame;
            RootFrame.Navigated -= CompleteInitializePhoneApplication;
        }

        /// <summary>Экран ошибки без XAML: он должен открыться, даже если сломан сам XAML.</summary>
        void ShowError(string what, Exception ex)
        {
            if (showingError) return;
            showingError = true;
            try
            {
                var panel = new StackPanel { Margin = new Thickness(24, 32, 24, 24) };
                panel.Children.Add(new TextBlock { Text = "HAPP", FontSize = 20 });
                panel.Children.Add(new TextBlock
                {
                    Text = "ошибка", FontSize = 64, Margin = new Thickness(-3, -8, 0, 12),
                    FontFamily = new FontFamily("Segoe WP Light")
                });
                panel.Children.Add(new TextBlock { Text = what, FontSize = 24, TextWrapping = TextWrapping.Wrap });
                panel.Children.Add(new TextBlock
                {
                    Text =
#if RELEASE
                        "Сделайте снимок экрана — по нему видно, что сломалось.\n\n" +
#else
                        "Журнал уже отправлен на мак.\n\n" +
#endif
                        Log.Describe(ex) + "\n\nжурнал:\n" + Log.Session,
                    FontSize = 16, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 24, 0, 0),
                    Foreground = new SolidColorBrush(Color.FromArgb(0xFF, 0x99, 0x99, 0x99))
                });
                var view = new ScrollViewer { Content = panel, Background = new SolidColorBrush(Colors.Black) };
                // RootVisual задаётся один раз: если кадр уже показан, кладём экран ошибки в него.
                if (RootVisual == null) RootVisual = view;
                else RootFrame.Content = view;
            }
            catch (Exception e2)
            {
                Log.Error("экран ошибки", e2);
            }
        }
    }
}
