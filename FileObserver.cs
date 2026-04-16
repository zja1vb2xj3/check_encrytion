using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CheckEncryption
{
    internal sealed class FileObserver : IDisposable
    {
        private readonly string _targetRoot;
        private readonly string _sessionName;

        private TraceEventSession? _session;
        private bool _isStopped;

        // 필터 그룹별 동적 배열
        private readonly Dictionary<EventFilterType, List<EventFilter>> _eventFilters;

        public FileObserver(string targetRoot, string sessionName = "CheckEncryption-FileIo")
        {
            _targetRoot = NormalizePath(targetRoot);
            _sessionName = sessionName;

            _eventFilters = new Dictionary<EventFilterType, List<EventFilter>>
            {
                { EventFilterType.ProcessName, new List<EventFilter>() },
                { EventFilterType.EventType, new List<EventFilter>() },
                { EventFilterType.PathContains, new List<EventFilter>() }
            };
        }

        public static bool IsAdministrator()
        {
            return TraceEventSession.IsElevated() == true;
        }

        public void EnableEventFilter(params EventFilter[] filters)
        {
            
            if (filters == null || filters.Length == 0)
            {
                return;
            }

            foreach (var filter in filters)
            {
                if (filter == null || string.IsNullOrWhiteSpace(filter.Value))
                {
                    continue;
                }

                var normalizedFilter = filter.Normalize();

                Console.WriteLine($"[FILTER-ADD] {normalizedFilter.Type} = '{normalizedFilter.Value}'");
                
                if (!_eventFilters.TryGetValue(normalizedFilter.Type, out var list))
                {
                    list = new List<EventFilter>();
                    _eventFilters[normalizedFilter.Type] = list;
                }

                if (!list.Any(x => x.EqualsTo(normalizedFilter)))
                {
                    list.Add(normalizedFilter);
                }
            }
        }

        public void DisableEventFilter(params EventFilter[] filters)
        {
            if (filters == null || filters.Length == 0)
            {
                return;
            }

            foreach (var filter in filters)
            {
                if (filter == null || string.IsNullOrWhiteSpace(filter.Value))
                {
                    continue;
                }

                var normalizedFilter = filter.Normalize();

                if (!_eventFilters.TryGetValue(normalizedFilter.Type, out var list))
                {
                    continue;
                }

                list.RemoveAll(x => x.EqualsTo(normalizedFilter));
            }
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

            if (ShouldSkipEvent(eventType, processName, normalizedFilePath))
            {
                return;
            }

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss.fff}] {eventType,-10} | {processName}({processId}) | {normalizedFilePath}"
            );
        }

        private bool ShouldSkipEvent(string eventType, string processName, string filePath)
        {
            var normalizedEventType = NormalizeToken(eventType);
            var normalizedProcessName = NormalizeProcessName(processName);
            var normalizedFilePath = NormalizePath(filePath);

            // 1) 프로세스명 필터
            if (_eventFilters.TryGetValue(EventFilterType.ProcessName, out var processFilters))
            {
                foreach (var filter in processFilters)
                {
                    if (normalizedProcessName == NormalizeProcessName(filter.Value))
                    {
                        return true;
                    }
                }
            }

            // 2) 이벤트명 필터
            if (_eventFilters.TryGetValue(EventFilterType.EventType, out var eventFilters))
            {
                foreach (var filter in eventFilters)
                {
                    if (normalizedEventType == NormalizeToken(filter.Value))
                    {
                        return true;
                    }
                }
            }

            // 3) 경로 포함 필터
            if (_eventFilters.TryGetValue(EventFilterType.PathContains, out var pathFilters))
            {
                foreach (var filter in pathFilters)
                {
                    var keyword = NormalizePathFragment(filter.Value);
                    if (!string.IsNullOrWhiteSpace(keyword) &&
                        normalizedFilePath.Contains(keyword, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static string NormalizeToken(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : value.Trim().ToLowerInvariant();
        }

        private static string NormalizeProcessName(string processName)
        {
            var normalized = NormalizeToken(processName);

            if (normalized.EndsWith(".exe", StringComparison.Ordinal))
            {
                normalized = normalized[..^4];
            }

            return normalized;
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

        private static string NormalizePathFragment(string pathFragment)
        {
            if (string.IsNullOrWhiteSpace(pathFragment))
            {
                return string.Empty;
            }

            return pathFragment.Replace('/', '\\').Trim().ToLowerInvariant();
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

    internal enum EventFilterType
    {
        ProcessName,
        EventType,
        PathContains
    }

    internal sealed class EventFilter
    {
        public EventFilterType Type { get; }
        public string Value { get; }

        public EventFilter(EventFilterType type, string value)
        {
            Type = type;
            Value = value ?? string.Empty;
        }

        public EventFilter Normalize()
        {
            return Type switch
            {
                EventFilterType.ProcessName => new EventFilter(Type, NormalizeProcess(Value)),
                EventFilterType.EventType => new EventFilter(Type, NormalizeText(Value)),
                EventFilterType.PathContains => new EventFilter(Type, NormalizePathText(Value)),
                _ => new EventFilter(Type, Value)
            };
        }

        public bool EqualsTo(EventFilter other)
        {
            if (other == null)
            {
                return false;
            }

            return Type == other.Type
                && string.Equals(Value, other.Value, StringComparison.OrdinalIgnoreCase);
        }

        public static EventFilter Process(string processName)
            => new EventFilter(EventFilterType.ProcessName, processName);

        public static EventFilter Event(string eventType)
            => new EventFilter(EventFilterType.EventType, eventType);

        public static EventFilter PathContains(string text)
            => new EventFilter(EventFilterType.PathContains, text);

        private static string NormalizeText(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : value.Trim().ToLowerInvariant();
        }

        private static string NormalizeProcess(string value)
        {
            var normalized = NormalizeText(value);

            if (normalized.EndsWith(".exe", StringComparison.Ordinal))
            {
                normalized = normalized[..^4];
            }

            return normalized;
        }

        private static string NormalizePathText(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : value.Replace('/', '\\').Trim().ToLowerInvariant();
        }
    }
}