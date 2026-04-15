using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.IO;

// 감시 대상 폴더
string targetRoot = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
    "Project",
    "goProject",
    "encryption_simulator",
    "testdata"
);

Console.WriteLine("ETW file I/O monitor starting...");
Console.WriteLine("Run this terminal/VS Code as Administrator.");
Console.WriteLine("Press Ctrl+C to stop.");
Console.WriteLine();

var sessionName = "CheckEncryption-FileIo";

using var session = new TraceEventSession(sessionName);
session.StopOnDispose = true;

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine();
    Console.WriteLine("Stopping session...");
    session.Dispose();
};

session.EnableKernelProvider(
    KernelTraceEventParser.Keywords.FileIOInit |
    KernelTraceEventParser.Keywords.FileIO
);

session.Source.Kernel.All += data =>
{
    string eventName = (data.EventName ?? string.Empty).ToLowerInvariant();

    // 1) 관심 이벤트만 통과
    if (!IsInterestingEvent(eventName))
        return;

    // 2) raw text 기준으로 경로 포함 여부 확인
    string raw = (data.ToString() ?? string.Empty)
        .Replace('/', '\\')
        .ToLowerInvariant();

    if (!ContainsTargetPath(raw, targetRoot))
        return;

    Console.WriteLine(
        $"[{DateTime.Now:HH:mm:ss.fff}] {data.EventName} | {data.ProcessName}({data.ProcessID}) | {raw}"
    );
};

session.Source.Process();

static bool IsInterestingEvent(string eventName)
{
    // 제외할 잡음 이벤트
    if (eventName.Contains("read")) return false;
    if (eventName.Contains("close")) return false;
    if (eventName.Contains("cleanup")) return false;
    if (eventName.Contains("query")) return false;
    if (eventName.Contains("direnum")) return false;
    if (eventName.Contains("dirnotify")) return false;

    // 보고 싶은 이벤트
    if (eventName.Contains("write")) return true;
    if (eventName.Contains("create")) return true;
    if (eventName.Contains("rename")) return true;
    if (eventName.Contains("delete")) return true;

    return false;
}

static bool ContainsTargetPath(string raw, string targetRoot)
{
    if (string.IsNullOrWhiteSpace(raw)) return false;
    if (string.IsNullOrWhiteSpace(targetRoot)) return false;

    return raw.Contains(targetRoot) || raw.Contains(targetRoot + "\\");
}