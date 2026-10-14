// Which syscalls CoreLib makes for the device-file operations a guest is most
// likely to perform. Each step writes a marker (a failed openat of a path
// naming the step) so the strace can be split per step.
using System;
using System.IO;

static class Program
{
    static void Mark(string step) { try { File.OpenHandle("/nonexistent-marker-" + step).Dispose(); } catch { } }

    static void Main()
    {
        Mark("exists"); Console.WriteLine(File.Exists("/dev/null"));
        Mark("length"); Console.WriteLine(new FileInfo("/dev/urandom").Length);
        Mark("openread");
        using (var fs = File.OpenRead("/dev/urandom"))
        {
            Mark("canseek"); Console.WriteLine(fs.CanSeek);
            Mark("read"); var b = new byte[16]; Console.WriteLine(fs.Read(b, 0, 16));
            Mark("read2"); Console.WriteLine(fs.Read(b, 0, 16));
            Mark("position"); Console.WriteLine(fs.Position);
            Mark("dispose");
        }
        Mark("writealltext"); File.WriteAllText("/dev/null", "hello");
        Mark("appendalltext"); File.AppendAllText("/dev/null", "hello");
        Mark("readallbytes"); Console.WriteLine(File.ReadAllBytes("/dev/null").Length);
        Mark("filestreamwrite");
        using (var fs = new FileStream("/dev/null", FileMode.Open, FileAccess.Write)) { fs.Write(new byte[5]); fs.Flush(true); }
        Mark("end");
    }
}
