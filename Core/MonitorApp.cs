using CheckEncryption.Infrastructure;
using CheckEncryption.Monitoring;
using System;
using System.IO;

namespace CheckEncryption.Core
{
    internal sealed class MonitorApp
    {
        private readonly AppSettings _settings;

        public MonitorApp(AppSettings settings)
        {
            _settings = settings;
        }

        public void Run()
        {
            using var logSession = new ConsoleLogSession(_settings.LogRootDir);
            uint? originalConsoleMode = ConsoleModeHelper.DisableQuickEdit();

            var resolvedTargetRoot = Path.GetFullPath(_settings.TargetRoot);

            try
            {
                PrintStartupBanner(resolvedTargetRoot);

                if (!FileObserver.IsAdministrator())
                {
                    Console.WriteLine("Administrator 권한으로 실행해야 합니다.");
                    return;
                }

                using var observer = new FileObserver(resolvedTargetRoot);

                foreach (var processName in _settings.ExcludedProcesses)
                {
                    observer.EnableEventFilter(EventFilter.Process(processName));
                }

                Console.CancelKeyPress += (_, e) =>
                {
                    Console.WriteLine();
                    Console.WriteLine("Stopping session...");
                    e.Cancel = true;
                    observer.Stop();
                };

                observer.Start();
            }
            finally
            {
                if (originalConsoleMode.HasValue)
                {
                    ConsoleModeHelper.RestoreMode(originalConsoleMode.Value);
                }
            }
        }

        private void PrintStartupBanner(string resolvedTargetRoot)
        {
            Console.WriteLine("ETW file I/O monitor starting...");
            Console.WriteLine("Run this terminal/VS Code as Administrator.");
            Console.WriteLine($"Monitoring path: {resolvedTargetRoot}");
            Console.WriteLine($"Current working directory: {Environment.CurrentDirectory}");
            Console.WriteLine("Press Ctrl+C to stop.");
            Console.WriteLine();
        }
    }
}