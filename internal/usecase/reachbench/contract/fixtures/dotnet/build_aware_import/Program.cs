using System.Reflection;
using Reachbench.Direct;

static class Program
{
    static void Main()
    {
        Entry.Run();
        var assemblyName = string.Concat("Reachbench", ".Dynamic");
        var typeName = string.Concat(assemblyName, ".Entry");
        var entry = Assembly.Load(assemblyName).GetType(typeName, throwOnError: true)!;
        entry.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, null);
    }
}
