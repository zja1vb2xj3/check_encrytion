using System;
using System.Runtime.InteropServices;

namespace CheckEncryption.Infrastructure
{
    internal static class ConsoleModeHelper
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        private const int STD_INPUT_HANDLE = -10;
        private const uint ENABLE_QUICK_EDIT_MODE = 0x0040;
        private const uint ENABLE_EXTENDED_FLAGS = 0x0080;

        public static uint? DisableQuickEdit()
        {
            var hInput = GetStdHandle(STD_INPUT_HANDLE);
            if (hInput == IntPtr.Zero || hInput == new IntPtr(-1))
            {
                return null;
            }

            if (!GetConsoleMode(hInput, out var mode))
            {
                return null;
            }

            var newMode = (mode | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE;

            if (!SetConsoleMode(hInput, newMode))
            {
                return null;
            }

            return mode;
        }

        public static void RestoreMode(uint originalMode)
        {
            var hInput = GetStdHandle(STD_INPUT_HANDLE);
            if (hInput == IntPtr.Zero || hInput == new IntPtr(-1))
            {
                return;
            }

            SetConsoleMode(hInput, originalMode);
        }
    }
}