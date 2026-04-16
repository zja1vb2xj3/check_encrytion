using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace CheckEncryption.Monitoring
{
    internal sealed class FileObserver : IDisposable
    {
        private readonly string _targetRoot;
        private readonly string _sessionName;

        private TraceEventSession? _session;
        private bool _isStopped;

        private readonly Dictionary<EventFilterType, List<EventFilter>> _eventFilters;
        private readonly Dictionary<string, ProcessWindowState> _processWindows;
        private readonly Dictionary<string, FileFlowState> _fileFlows;

        private static readonly TimeSpan BehaviorWindow = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan BehaviorAlertCooldown = TimeSpan.FromSeconds(3);

        private static readonly TimeSpan FlowWindow = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan FlowEmitCooldown = TimeSpan.FromMilliseconds(700);

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

            _processWindows = new Dictionary<string, ProcessWindowState>(StringComparer.OrdinalIgnoreCase);
            _fileFlows = new Dictionary<string, FileFlowState>(StringComparer.OrdinalIgnoreCase);
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

            _session = null;
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

            kernel.FileIOFileCreate += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Create32,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOCreate += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Create64,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIORead += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Read67,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOWrite += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Write68,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOQueryInfo += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.QueryInfo74,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIORename += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Rename71,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIODelete += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Delete70,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOFileDelete += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.FileDelete35,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOCleanup += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Cleanup65,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOClose += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Close66,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIODirEnum += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.DirEnum72,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };

            kernel.FileIOFlush += data =>
            {
                HandleRawEvent(
                    RawFileEventKind.Flush73,
                    GetStringProperty(data, "ProcessName"),
                    GetIntProperty(data, "ProcessID", "ProcessId"),
                    GetPathProperty(data));
            };
        }

        private void HandleRawEvent(RawFileEventKind kind, string processName, int processId, string rawPath)
        {
            var eventName = kind.ToString();
            var effectiveProcessName = string.IsNullOrWhiteSpace(processName) ? "Unknown" : processName.Trim();
            var normalizedPath = NormalizePath(rawPath);

            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                return;
            }

            if (!IsUnderTarget(normalizedPath, _targetRoot))
            {
                return;
            }

            if (ShouldSkipEvent(eventName, effectiveProcessName, normalizedPath))
            {
                return;
            }

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss.fff}] {eventName,-12} | {effectiveProcessName}({processId}) | {normalizedPath} | {GetMeaning(kind)}");
            Console.Out.Flush();

            RegisterFlowObservation(kind, effectiveProcessName, processId, normalizedPath);
            RegisterBehaviorObservation(kind, effectiveProcessName, processId, normalizedPath);
        }

        private void RegisterFlowObservation(RawFileEventKind kind, string processName, int processId, string path)
        {
            var now = DateTime.Now;
            var flowKey = $"{NormalizeProcessName(processName)}:{processId}:{path}";

            if (!_fileFlows.TryGetValue(flowKey, out var state))
            {
                state = new FileFlowState(processName, processId, path);
                _fileFlows[flowKey] = state;
            }

            state.Add(new FileObservation(now, kind, processName, processId, path));
            state.Prune(now - FlowWindow);

            var evaluation = state.Evaluate(now);
            if (!evaluation.ShouldEmit)
            {
                return;
            }

            if (evaluation.Label == state.LastEmittedLabel &&
                now - state.LastEmittedAt < FlowEmitCooldown)
            {
                return;
            }

            state.LastEmittedLabel = evaluation.Label;
            state.LastEmittedAt = now;
            
            Console.WriteLine(
                $"[FLOW {now:HH:mm:ss.fff}] {evaluation.Label,-13} | {processName}({processId}) | {path} | " +
                $"Basis={evaluation.Basis} | Reads={evaluation.Reads} | Writes={evaluation.Writes} | Query={evaluation.Queries} | Creates={evaluation.Creates}");
            Console.WriteLine();
            
            Console.Out.Flush();
        }

        private void RegisterBehaviorObservation(RawFileEventKind kind, string processName, int processId, string path)
        {
            var now = DateTime.Now;
            var processKey = $"{NormalizeProcessName(processName)}:{processId}";

            if (!_processWindows.TryGetValue(processKey, out var state))
            {
                state = new ProcessWindowState(processName, processId);
                _processWindows[processKey] = state;
            }

            state.Add(new FileObservation(now, kind, processName, processId, path));
            state.Prune(now - BehaviorWindow);

            var evaluation = state.Evaluate(now);
            if (!evaluation.ShouldAlert)
            {
                return;
            }

            if (now - state.LastAlertTime < BehaviorAlertCooldown)
            {
                return;
            }

            state.LastAlertTime = now;

            Console.WriteLine(
                $"[ACT  {now:HH:mm:ss.fff}] {evaluation.Level,-14} | {processName}({processId}) | " +
                $"Score={evaluation.Score} | Win=10s | Events={evaluation.TotalEvents} | Files={evaluation.UniqueFiles} | " +
                $"Reads={evaluation.Reads} | Writes={evaluation.Writes} | Renames={evaluation.Renames} | Deletes={evaluation.Deletes} | DirEnum={evaluation.DirEnums} | " +
                $"Creates={evaluation.Creates} | Query={evaluation.Queries} | Reasons={string.Join(", ", evaluation.Reasons)}");
            Console.Out.Flush();
        }

        private bool ShouldSkipEvent(string eventType, string processName, string filePath)
        {
            var normalizedEventType = NormalizeToken(eventType);
            var normalizedProcessName = NormalizeProcessName(processName);
            var normalizedFilePath = NormalizePath(filePath);

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

        private static string GetMeaning(RawFileEventKind kind)
        {
            return kind switch
            {
                RawFileEventKind.Create32 => "NameCreate/FileCreate",
                RawFileEventKind.Create64 => "Open/CreateCandidate",
                RawFileEventKind.Read67 => "DataRead",
                RawFileEventKind.Write68 => "DataWrite",
                RawFileEventKind.Rename71 => "NameChange",
                RawFileEventKind.Delete70 => "DeleteCandidate",
                RawFileEventKind.FileDelete35 => "FileDelete",
                RawFileEventKind.Cleanup65 => "LastHandleReleased",
                RawFileEventKind.Close66 => "FileObjectFreed",
                RawFileEventKind.DirEnum72 => "DirectoryEnumeration",
                RawFileEventKind.Flush73 => "BufferFlushToDisk",
                RawFileEventKind.QueryInfo74 => "QueryFileInformation",
                _ => "Unknown"
            };
        }

        private static string GetPathProperty(object eventData)
        {
            return GetStringProperty(
                eventData,
                "FileName",
                "DirectoryName",
                "OpenPath",
                "Path");
        }

        private static string GetStringProperty(object target, params string[] propertyNames)
        {
            if (target == null)
            {
                return string.Empty;
            }

            var type = target.GetType();

            foreach (var propertyName in propertyNames)
            {
                var property = type.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
                if (property == null)
                {
                    continue;
                }

                var value = property.GetValue(target);
                if (value == null)
                {
                    continue;
                }

                return value.ToString() ?? string.Empty;
            }

            return string.Empty;
        }

        private static int GetIntProperty(object target, params string[] propertyNames)
        {
            if (target == null)
            {
                return 0;
            }

            var type = target.GetType();

            foreach (var propertyName in propertyNames)
            {
                var property = type.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
                if (property == null)
                {
                    continue;
                }

                var value = property.GetValue(target);
                if (value == null)
                {
                    continue;
                }

                if (value is int intValue)
                {
                    return intValue;
                }

                if (int.TryParse(value.ToString(), out var parsed))
                {
                    return parsed;
                }
            }

            return 0;
        }

        private static string NormalizeToken(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : value.Trim().ToLowerInvariant();
        }

        private static string NormalizeProcessName(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
            {
                return string.Empty;
            }

            var normalized = processName.Trim();
            normalized = Path.GetFileName(normalized);

            if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                normalized = Path.GetFileNameWithoutExtension(normalized);
            }

            return normalized.Trim().ToLowerInvariant();
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

            normalized = normalized.ToLowerInvariant();

            if (normalized.Length > 3)
            {
                normalized = normalized.TrimEnd('\\');
            }

            return normalized;
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

    internal enum RawFileEventKind
    {
        Create32,
        Create64,
        Read67,
        Write68,
        Rename71,
        Delete70,
        FileDelete35,
        Cleanup65,
        Close66,
        DirEnum72,
        Flush73,
        QueryInfo74
    }

    internal sealed class FileObservation
    {
        public FileObservation(
            DateTime timestamp,
            RawFileEventKind kind,
            string processName,
            int processId,
            string path)
        {
            Timestamp = timestamp;
            Kind = kind;
            ProcessName = processName;
            ProcessId = processId;
            Path = path;
        }

        public DateTime Timestamp { get; }
        public RawFileEventKind Kind { get; }
        public string ProcessName { get; }
        public int ProcessId { get; }
        public string Path { get; }
    }

    internal sealed class FileFlowState
    {
        private readonly Queue<FileObservation> _observations = new Queue<FileObservation>();

        public FileFlowState(string processName, int processId, string path)
        {
            ProcessName = processName;
            ProcessId = processId;
            Path = path;
            LastEmittedAt = DateTime.MinValue;
            LastEmittedLabel = string.Empty;
        }

        public string ProcessName { get; }
        public int ProcessId { get; }
        public string Path { get; }
        public DateTime LastEmittedAt { get; set; }
        public string LastEmittedLabel { get; set; }

        public void Add(FileObservation observation)
        {
            _observations.Enqueue(observation);
        }

        public void Prune(DateTime threshold)
        {
            while (_observations.Count > 0 && _observations.Peek().Timestamp < threshold)
            {
                _observations.Dequeue();
            }
        }

        public FileFlowEvaluation Evaluate(DateTime now)
        {
            var snapshot = _observations.ToArray();

            var creates = snapshot.Count(x => x.Kind == RawFileEventKind.Create32 || x.Kind == RawFileEventKind.Create64);
            var reads = snapshot.Count(x => x.Kind == RawFileEventKind.Read67);
            var writes = snapshot.Count(x => x.Kind == RawFileEventKind.Write68);
            var queries = snapshot.Count(x => x.Kind == RawFileEventKind.QueryInfo74);
            var cleanups = snapshot.Count(x => x.Kind == RawFileEventKind.Cleanup65);
            var closes = snapshot.Count(x => x.Kind == RawFileEventKind.Close66);

            var presentKinds = snapshot
                .Select(x => x.Kind.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x)
                .ToArray();

            var basis = string.Join("+", presentKinds);

            if (creates >= 1 && writes >= 1)
            {
                return new FileFlowEvaluation(true, "WriteFileLike", basis, creates, reads, writes, queries, cleanups, closes);
            }

            if ((creates >= 1 || queries >= 1) && reads >= 1 && writes == 0)
            {
                return new FileFlowEvaluation(true, "ReadFileLike", basis, creates, reads, writes, queries, cleanups, closes);
            }

            if (queries >= 1 && reads == 0 && writes == 0)
            {
                return new FileFlowEvaluation(false, "MetadataQueryLike", basis, creates, reads, writes, queries, cleanups, closes);
            }

            return new FileFlowEvaluation(false, string.Empty, basis, creates, reads, writes, queries, cleanups, closes);
        }
    }

    internal sealed class FileFlowEvaluation
    {
        public FileFlowEvaluation(
            bool shouldEmit,
            string label,
            string basis,
            int creates,
            int reads,
            int writes,
            int queries,
            int cleanups,
            int closes)
        {
            ShouldEmit = shouldEmit;
            Label = label;
            Basis = basis;
            Creates = creates;
            Reads = reads;
            Writes = writes;
            Queries = queries;
            Cleanups = cleanups;
            Closes = closes;
        }

        public bool ShouldEmit { get; }
        public string Label { get; }
        public string Basis { get; }
        public int Creates { get; }
        public int Reads { get; }
        public int Writes { get; }
        public int Queries { get; }
        public int Cleanups { get; }
        public int Closes { get; }
    }

    internal sealed class ProcessWindowState
    {
        private readonly Queue<FileObservation> _observations = new Queue<FileObservation>();

        public ProcessWindowState(string processName, int processId)
        {
            ProcessName = processName;
            ProcessId = processId;
            LastAlertTime = DateTime.MinValue;
        }

        public string ProcessName { get; }
        public int ProcessId { get; }
        public DateTime LastAlertTime { get; set; }

        public void Add(FileObservation observation)
        {
            _observations.Enqueue(observation);
        }

        public void Prune(DateTime threshold)
        {
            while (_observations.Count > 0 && _observations.Peek().Timestamp < threshold)
            {
                _observations.Dequeue();
            }
        }

        public BehaviorEvaluation Evaluate(DateTime now)
        {
            var snapshot = _observations.ToArray();

            var totalEvents = snapshot.Length;
            var creates = snapshot.Count(x => x.Kind == RawFileEventKind.Create32 || x.Kind == RawFileEventKind.Create64);
            var reads = snapshot.Count(x => x.Kind == RawFileEventKind.Read67);
            var writes = snapshot.Count(x => x.Kind == RawFileEventKind.Write68);
            var queries = snapshot.Count(x => x.Kind == RawFileEventKind.QueryInfo74);
            var renames = snapshot.Count(x => x.Kind == RawFileEventKind.Rename71);
            var deletes = snapshot.Count(x => x.Kind == RawFileEventKind.Delete70 || x.Kind == RawFileEventKind.FileDelete35);
            var dirEnums = snapshot.Count(x => x.Kind == RawFileEventKind.DirEnum72);
            var cleanups = snapshot.Count(x => x.Kind == RawFileEventKind.Cleanup65);
            var closes = snapshot.Count(x => x.Kind == RawFileEventKind.Close66);
            var flushes = snapshot.Count(x => x.Kind == RawFileEventKind.Flush73);

            var uniqueFiles = snapshot
                .Where(x => !string.IsNullOrWhiteSpace(x.Path))
                .Select(x => x.Path)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            var uniqueDirs = snapshot
                .Select(x => SafeGetDirectoryName(x.Path))
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            var score = 0;
            var reasons = new List<string>();

            if (writes >= 10)
            {
                score += 20;
                reasons.Add($"writes={writes}");
            }

            if (writes >= 20)
            {
                score += 15;
                reasons.Add("high-write-rate");
            }

            if (uniqueFiles >= 10)
            {
                score += 15;
                reasons.Add($"unique-files={uniqueFiles}");
            }

            if (uniqueFiles >= 20)
            {
                score += 15;
                reasons.Add("wide-file-spread");
            }

            if (renames >= 5)
            {
                score += 25;
                reasons.Add($"renames={renames}");
            }

            if (deletes >= 5)
            {
                score += 25;
                reasons.Add($"deletes={deletes}");
            }

            if (dirEnums >= 1 && uniqueFiles >= 10)
            {
                score += 10;
                reasons.Add("dir-scan-before-mass-file-touch");
            }

            if (queries >= 10 && reads >= 10 && writes == 0)
            {
                score += 5;
                reasons.Add("heavy-read-scan");
            }

            if (writes >= 8 && flushes >= 3)
            {
                score += 10;
                reasons.Add("write-flush-loop");
            }

            if (writes >= 8 && cleanups >= 8 && closes >= 8)
            {
                score += 10;
                reasons.Add("handle-churn");
            }

            if (uniqueDirs >= 3 && uniqueFiles >= 10)
            {
                score += 10;
                reasons.Add($"multi-dir={uniqueDirs}");
            }

            string level;
            bool shouldAlert;

            if (score >= 70)
            {
                level = "LIKELY_ATTACK";
                shouldAlert = true;
            }
            else if (score >= 40)
            {
                level = "SUSPICIOUS";
                shouldAlert = true;
            }
            else
            {
                level = "NORMAL_LIKE";
                shouldAlert = false;
            }

            return new BehaviorEvaluation(
                shouldAlert,
                level,
                score,
                totalEvents,
                uniqueFiles,
                reads,
                writes,
                queries,
                renames,
                deletes,
                dirEnums,
                creates,
                reasons);
        }

        private static string SafeGetDirectoryName(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetDirectoryName(path) ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    internal sealed class BehaviorEvaluation
    {
        public BehaviorEvaluation(
            bool shouldAlert,
            string level,
            int score,
            int totalEvents,
            int uniqueFiles,
            int reads,
            int writes,
            int queries,
            int renames,
            int deletes,
            int dirEnums,
            int creates,
            List<string> reasons)
        {
            ShouldAlert = shouldAlert;
            Level = level;
            Score = score;
            TotalEvents = totalEvents;
            UniqueFiles = uniqueFiles;
            Reads = reads;
            Writes = writes;
            Queries = queries;
            Renames = renames;
            Deletes = deletes;
            DirEnums = dirEnums;
            Creates = creates;
            Reasons = reasons;
        }

        public bool ShouldAlert { get; }
        public string Level { get; }
        public int Score { get; }
        public int TotalEvents { get; }
        public int UniqueFiles { get; }
        public int Reads { get; }
        public int Writes { get; }
        public int Queries { get; }
        public int Renames { get; }
        public int Deletes { get; }
        public int DirEnums { get; }
        public int Creates { get; }
        public List<string> Reasons { get; }
    }

    internal enum EventFilterType
    {
        ProcessName,
        EventType,
        PathContains
    }

    internal sealed class EventFilter
    {
        public EventFilter(EventFilterType type, string value)
        {
            Type = type;
            Value = value ?? string.Empty;
        }

        public EventFilterType Type { get; }
        public string Value { get; }

        public static EventFilter Process(string processName)
            => new EventFilter(EventFilterType.ProcessName, processName);

        public static EventFilter Event(string eventType)
            => new EventFilter(EventFilterType.EventType, eventType);

        public static EventFilter PathContains(string text)
            => new EventFilter(EventFilterType.PathContains, text);

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

        private static string NormalizeText(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : value.Trim().ToLowerInvariant();
        }

        private static string NormalizeProcess(string value)
        {
            var normalized = NormalizeText(value);
            normalized = Path.GetFileName(normalized);

            if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                normalized = Path.GetFileNameWithoutExtension(normalized);
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