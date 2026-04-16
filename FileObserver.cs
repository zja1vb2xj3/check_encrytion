using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.IO;

namespace CheckEncryption
{
    internal sealed class FileObserver : IDisposable
    {
        private readonly string _targetRoot;
        private readonly string _sessionName;
        private TraceEventSession? _session;
        private bool _isStopped;

        public FileObserver(string targetRoot, string sessionName = "CheckEncryption-FileIo")
        {
            _targetRoot = NormalizePath(targetRoot);
            _sessionName = sessionName;
        }

        public static bool IsAdministrator()
        {
            return TraceEventSession.IsElevated() == true;
        }

        public void Start()
        {
            if (_session is not null)
            {
                throw new InvalidOperationException("Observer is already started.");
            }

            _session = new TraceEventSession(_sessionName)
            {
                StopOnDispose = true
            };

            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO
            );

            RegisterEventHandlers(_session);

            try
            {
                _session.Source.Process();
            }
            finally
            {
                Dispose();
            }
        }

        public void Stop()
        {
            if (_isStopped)
            {
                return;
            }

            _isStopped = true;

            try
            {
                _session?.Source.StopProcessing();
            }
            catch
            {
            }

            try
            {
                _session?.Dispose();
            }
            catch
            {
            }
        }

        public void Dispose()
        {
            if (_isStopped && _session is null)
            {
                return;
            }

            _isStopped = true;

            try
            {
                _session?.Dispose();
            }
            catch
            {
            }
            finally
            {
                _session = null;
            }
        }

        private void RegisterEventHandlers(TraceEventSession session)
        {
            var kernel = session.Source.Kernel;

            kernel.FileIOCreate += data =>
            {
                HandleEvent("Create", data.ProcessName, data.ProcessID, data.FileName);
            };

            kernel.FileIOFileCreate += data =>
            {
                HandleEvent("FileCreate", data.ProcessName, data.ProcessID, data.FileName);
            };

            kernel.FileIOWrite += data =>
            {
                HandleEvent("Write", data.ProcessName, data.ProcessID, data.FileName);
            };

            kernel.FileIORename += data =>
            {
                HandleEvent("Rename", data.ProcessName, data.ProcessID, data.FileName);
            };

            kernel.FileIODelete += data =>
            {
                HandleEvent("Delete", data.ProcessName, data.ProcessID, data.FileName);
            };

            kernel.FileIOFileDelete += data =>
            {
                HandleEvent("FileDelete", data.ProcessName, data.ProcessID, data.FileName);
            };
        }

        private void HandleEvent(string eventType, string processName, int processId, string fileName)
        {
            var normalizedFilePath = NormalizePath(fileName);

            if (string.IsNullOrWhiteSpace(normalizedFilePath))
            {
                return;
            }

            if (!IsUnderTarget(normalizedFilePath, _targetRoot))
            {
                return;
            }

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss.fff}] {eventType,-10} | {processName}({processId}) | {normalizedFilePath}"
            );
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            var normalized = path.Replace('/', '\\').Trim();

            try
            {
                if (normalized.Length >= 2 && normalized[1] == ':')
                {
                    normalized = Path.GetFullPath(normalized);
                }
            }
            catch
            {
            }

            return normalized.TrimEnd('\\').ToLowerInvariant();
        }

        private static bool IsUnderTarget(string filePath, string targetRoot)
        {
            if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(targetRoot))
            {
                return false;
            }

            return filePath == targetRoot
                   || filePath.StartsWith(targetRoot + "\\", StringComparison.Ordinal);
        }
    }
}