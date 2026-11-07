using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace HappWP
{
    /// <summary>true / непустая строка → Visible.</summary>
    public class VisibleIf : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool on = value is bool ? (bool)value : value is string ? ((string)value).Length > 0 : value != null;
            return on ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>Выбранный сервер подсвечивается цветом темы, как выбранный пункт в системных списках.</summary>
    public class AccentIf : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string key = value is bool && (bool)value ? "PhoneAccentBrush" : "PhoneForegroundBrush";
            return (Brush)Application.Current.Resources[key];
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
