using System;
using System.IO;

namespace CheckEncryption
{
    internal static class Program
    {
        private static void Main()
        {
            var targetRoot = @"C:\Users\donggwan.park\Desktop\Project\goProject\encryption_simulator\testdata";

            Console.WriteLine("ETW file I/O monitor starting...");
            Console.WriteLine("Run this terminal/VS Code as Administrator.");
            Console.WriteLine($"Monitoring path: {targetRoot}");
            Console.WriteLine(Directory.Exists(targetRoot)
                ? "Target folder exists."
                : "Target folder does NOT exist.");
            Console.WriteLine("Press Ctrl+C to stop.");
            Console.WriteLine();

            if (!FileObserver.IsAdministrator())
            {
                Console.WriteLine("Administrator 권한으로 실행해야 합니다.");
                return;
            }

            using var observer = new FileObserver(targetRoot);

            observer.EnableEventFilter(
                EventFilter.Process("explorer"),
                EventFilter.Process("System"),
                EventFilter.Process("SearchProtocolHost"),
                EventFilter.Process("SearchIndexer"),
                EventFilter.Process("Code")
            );

            // 예시:
            // observer.EnableEventFilter(EventFilter.Event("Write"));
            // observer.EnableEventFilter(EventFilter.PathContains(@"\temp\"));

            // 특정 필터만 해제
            // observer.DisableEventFilter(EventFilter.Process("System"));

            Console.CancelKeyPress += (_, e) =>
            {
                Console.WriteLine();
                Console.WriteLine("Stopping session...");
                e.Cancel = true;
                observer.Stop();
            };

            observer.Start();
        }
    }
}