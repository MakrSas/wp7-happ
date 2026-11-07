// После mcs: конструктор ComImport-класса делаем как у csc — «runtime managed internalcall».
// mcs оставляет «cil managed internalcall», а свой конструктор у ComImport-класса объявить не даёт.
//
//   mono fixcom.exe <ref-dir> <lib-dir> SimEmu.dll
using System;
using Mono.Cecil;

static class FixCom
{
    static int Main(string[] a)
    {
        var resolver = new DefaultAssemblyResolver();
        resolver.AddSearchDirectory(a[0]);
        resolver.AddSearchDirectory(a[1]);
        string path = a[2];
        var asm = AssemblyDefinition.ReadAssembly(path, new ReaderParameters { AssemblyResolver = resolver, InMemory = true });
        int n = 0;
        foreach (var t in asm.MainModule.Types)
        {
            if (!t.IsImport || t.IsInterface) continue;
            foreach (var m in t.Methods)
            {
                if (!m.IsConstructor || m.IsStatic) continue;
                m.ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed | MethodImplAttributes.InternalCall;
                n++;
                Console.WriteLine("fixcom: " + t.FullName + "::.ctor → runtime managed internalcall");
            }
        }
        asm.Write(path);
        Console.WriteLine("fixcom: исправлено конструкторов: " + n + ", runtime " + asm.MainModule.RuntimeVersion);
        return n > 0 ? 0 : 1;
    }
}
