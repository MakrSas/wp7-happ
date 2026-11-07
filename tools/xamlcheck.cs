// Проверка XAML против reference-сборок WP 7.1: каждый элемент — существующий тип, каждый атрибут —
// свойство, событие или attached-свойство, ключи StaticResource — из темы телефона или из словарей.
// Запускается в mono на сборочной машине: телефон XAML не валидирует при сборке, а падает при старте.
//
//   mono xamlcheck.exe <ref-dir> <lib-dir> <SimEmu.dll> file.xaml...
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Linq;

static class XamlCheck
{
    const string X = "http://schemas.microsoft.com/winfx/2006/xaml";
    const string P = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

    static readonly string[] DefaultNs =
    {
        "System.Windows", "System.Windows.Controls", "System.Windows.Shapes", "System.Windows.Documents",
        "System.Windows.Media", "System.Windows.Media.Animation", "System.Windows.Controls.Primitives", "System.Windows.Data",
    };

    // Ресурсы темы Windows Phone (ThemeResources.xaml в SDK).
    static readonly HashSet<string> Theme = new HashSet<string>
    {
        "PhoneFontFamilyNormal", "PhoneFontFamilyLight", "PhoneFontFamilySemiLight", "PhoneFontFamilySemiBold",
        "PhoneFontSizeSmall", "PhoneFontSizeNormal", "PhoneFontSizeMedium", "PhoneFontSizeMediumLarge", "PhoneFontSizeLarge",
        "PhoneFontSizeExtraLarge", "PhoneFontSizeExtraExtraLarge", "PhoneFontSizeHuge",
        "PhoneForegroundBrush", "PhoneBackgroundBrush", "PhoneAccentBrush", "PhoneChromeBrush", "PhoneSubtleBrush",
        "PhoneContrastBackgroundBrush", "PhoneDisabledBrush", "PhoneBorderBrush",
        "PhoneTextNormalStyle", "PhoneTextSubtleStyle", "PhoneTextLargeStyle", "PhoneTextExtraLargeStyle",
        "PhoneTextTitle1Style", "PhoneTextTitle2Style", "PhoneTextTitle3Style", "PhoneTextAccentStyle", "PhoneTextSmallStyle",
        "PhoneTextGroupHeaderStyle", "PhoneTextContrastStyle",
    };

    static readonly List<Assembly> Asms = new List<Assembly>();
    static string[] a0;
    static int errors;

    static int Main(string[] a)
    {
        a0 = a;
        var dirs = new[] { a[0], a[1] };
        AppDomain.CurrentDomain.ReflectionOnlyAssemblyResolve += (s, e) =>
        {
            var n = new AssemblyName(e.Name).Name;
            foreach (var d in dirs)
            {
                var p = Path.Combine(d, n + ".dll");
                if (File.Exists(p)) return Assembly.ReflectionOnlyLoadFrom(p);
            }
            return null;
        };
        foreach (var d in dirs)
            foreach (var f in Directory.GetFiles(d, "*.dll"))
                Asms.Add(Assembly.ReflectionOnlyLoadFrom(f));
        Asms.Add(Assembly.ReflectionOnlyLoadFrom(a[2]));

        var keys = new HashSet<string>(Theme);
        var docs = a.Skip(3).Select(f => new { f, doc = XDocument.Load(f, LoadOptions.SetLineInfo) }).ToList();
        foreach (var d in docs)
            foreach (var el in d.doc.Descendants())
            {
                var k = (string)el.Attribute(XName.Get("Key", X));
                if (k != null) keys.Add(k);
            }
        foreach (var d in docs) Check(d.f, d.doc.Root, keys);
        Console.WriteLine(errors == 0 ? "xamlcheck: ошибок нет" : "xamlcheck: ошибок " + errors);
        return errors == 0 ? 0 : 1;
    }

    static void Err(string file, XObject o, string msg)
    {
        var li = (System.Xml.IXmlLineInfo)o;
        Console.WriteLine("{0}:{1}: {2}", file, li.LineNumber, msg);
        errors++;
    }

    static Type Resolve(XName name, XElement scope)
    {
        string ns = name.NamespaceName, local = name.LocalName;
        if (ns == P)
        {
            foreach (var n in DefaultNs)
                foreach (var asm in Asms)
                {
                    var t = asm.GetType(n + "." + local);
                    if (t != null && t.IsPublic) return t;
                }
            return null;
        }
        if (ns.StartsWith("clr-namespace:"))
        {
            var parts = ns.Substring(14).Split(';');
            var asmName = parts.Length > 1 ? parts[1].Replace("assembly=", "") : Path.GetFileNameWithoutExtension(a0[2]);
            foreach (var asm in Asms)
                if (asm.GetName().Name == asmName)
                    return asm.GetType(parts[0] + "." + local);
        }
        return null;
    }

    static MemberInfo Member(Type t, string name)
    {
        for (var c = t; c != null; c = c.BaseType)
        {
            var p = c.GetProperty(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            if (p != null) return p;
            var e = c.GetEvent(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            if (e != null) return e;
        }
        return null;
    }

    static void CheckResources(string file, XAttribute at, HashSet<string> keys)
    {
        var v = at.Value.Trim();
        if (!v.StartsWith("{StaticResource ")) return;
        var k = v.Substring(16).TrimEnd('}').Trim();
        if (!keys.Contains(k)) Err(file, at, "нет ресурса " + k);
    }

    static void Check(string file, XElement el, HashSet<string> keys)
    {
        string local = el.Name.LocalName;
        int dot = local.IndexOf('.');
        if (dot > 0)
        {
            // Свойство-элемент: Grid.ColumnDefinitions, phone:PhoneApplicationPage.Resources
            var owner = Resolve(XName.Get(local.Substring(0, dot), el.Name.NamespaceName), el);
            if (owner == null) Err(file, el, "нет типа " + local.Substring(0, dot));
            else if (Member(owner, local.Substring(dot + 1)) == null) Err(file, el, owner.Name + " без свойства " + local.Substring(dot + 1));
            foreach (var c in el.Elements()) Check(file, c, keys);
            return;
        }
        var t = Resolve(el.Name, el);
        if (t == null)
        {
            Err(file, el, "нет типа " + el.Name);
            return;
        }
        foreach (var at in el.Attributes())
        {
            if (at.IsNamespaceDeclaration || at.Name.NamespaceName == X) continue;
            CheckResources(file, at, keys);
            string an = at.Name.LocalName;
            int d = an.IndexOf('.');
            if (d > 0)
            {
                var ns = at.Name.NamespaceName == "" ? el.Name.NamespaceName : at.Name.NamespaceName;
                var owner = Resolve(XName.Get(an.Substring(0, d), ns), el);
                if (owner == null) { Err(file, at, "нет типа " + an.Substring(0, d)); continue; }
                var setter = owner.GetMethod("Set" + an.Substring(d + 1), BindingFlags.Public | BindingFlags.Static);
                if (setter == null && Member(owner, an.Substring(d + 1)) == null) Err(file, at, "нет attached-свойства " + an);
                continue;
            }
            // Setter Property="..." в стиле: свойство целевого типа
            if (t.Name == "Setter" && an == "Property")
            {
                var style = el.Parent;
                var tt = style == null ? null : (string)style.Attribute("TargetType");
                var target = tt == null ? null : Resolve(XName.Get(tt, P), style);
                if (target != null && Member(target, at.Value) == null) Err(file, at, target.Name + " без свойства " + at.Value);
                continue;
            }
            if (Member(t, an) == null) Err(file, at, t.Name + " без свойства/события " + an);
        }
        foreach (var c in el.Elements()) Check(file, c, keys);
    }
}
