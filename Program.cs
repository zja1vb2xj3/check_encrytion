using CheckEncryption.Core;

namespace CheckEncryption
{
    internal static class Program
    {
        private static void Main()
        {
            var settings = AppSettings.CreateDefault();
            var app = new MonitorApp(settings);
            app.Run();
        }
    }
}