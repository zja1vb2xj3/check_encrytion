using System;
using System.IO;
using System.Text;

namespace CheckEncryption.Infrastructure
{
    internal sealed class ConsoleLogSession : IDisposable
    {
        private readonly string _logRootDir;
        private readonly string _tempLogPath;

        private readonly TextWriter _originalOut;
        private readonly TextWriter _originalError;
        private readonly StreamWriter _logFileWriter;
        private readonly TeeTextWriter _teeOutWriter;
        private readonly TeeTextWriter _teeErrorWriter;

        private bool _disposed;

        public ConsoleLogSession(string logRootDir)
        {
            _logRootDir = logRootDir;
            Directory.CreateDirectory(_logRootDir);

            _tempLogPath = Path.Combine(_logRootDir, "console_current.txt");

            _originalOut = Console.Out;
            _originalError = Console.Error;

            _logFileWriter = new StreamWriter(_tempLogPath, append: false, Encoding.UTF8)
            {
                AutoFlush = true
            };

            _teeOutWriter = new TeeTextWriter(_originalOut, _logFileWriter);
            _teeErrorWriter = new TeeTextWriter(_originalError, _logFileWriter);

            Console.SetOut(_teeOutWriter);
            Console.SetError(_teeErrorWriter);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                _teeOutWriter.Flush();
                _teeErrorWriter.Flush();
                _logFileWriter.Flush();
            }
            catch
            {
            }

            try
            {
                Console.SetOut(_originalOut);
                Console.SetError(_originalError);
            }
            catch
            {
            }

            try
            {
                _teeOutWriter.Dispose();
                _teeErrorWriter.Dispose();
                _logFileWriter.Dispose();
            }
            catch
            {
            }

            FinalizeLogFile();
        }

        private void FinalizeLogFile()
        {
            try
            {
                var finalLogPath = Path.Combine(
                    _logRootDir,
                    $"{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.txt");

                if (File.Exists(_tempLogPath))
                {
                    if (File.Exists(finalLogPath))
                    {
                        File.Delete(finalLogPath);
                    }

                    File.Move(_tempLogPath, finalLogPath);
                }

                Console.WriteLine($"콘솔 로그 저장 완료: {finalLogPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"콘솔 로그 저장 실패: {ex.Message}");
            }
        }
    }
}