using System;
using System.IO;
using System.Text;

namespace CheckEncryption.Infrastructure
{
    internal sealed class TeeTextWriter : TextWriter
    {
        private readonly TextWriter _consoleWriter;
        private readonly TextWriter _fileWriter;

        public TeeTextWriter(TextWriter consoleWriter, TextWriter fileWriter)
        {
            _consoleWriter = consoleWriter;
            _fileWriter = fileWriter;
        }

        public override Encoding Encoding => _consoleWriter.Encoding;

        public override void Write(char value)
        {
            _consoleWriter.Write(value);
            _fileWriter.Write(value);
        }

        public override void Write(string? value)
        {
            _consoleWriter.Write(value);
            _fileWriter.Write(value);
        }

        public override void WriteLine()
        {
            _consoleWriter.WriteLine();
            _fileWriter.WriteLine();
        }

        public override void WriteLine(string? value)
        {
            _consoleWriter.WriteLine(value);
            _fileWriter.WriteLine(value);
        }

        public override void Write(ReadOnlySpan<char> buffer)
        {
            _consoleWriter.Write(buffer);
            _fileWriter.Write(buffer);
        }

        public override void WriteLine(ReadOnlySpan<char> buffer)
        {
            _consoleWriter.WriteLine(buffer);
            _fileWriter.WriteLine(buffer);
        }

        public override void Flush()
        {
            _consoleWriter.Flush();
            _fileWriter.Flush();
        }
    }
}