namespace CheckEncryption.Core
{
    internal sealed class AppSettings
    {
        public string TargetRoot { get; init; } = @"..\..\goProject\encryption_simulator\testdata";
        public string LogRootDir { get; init; } = "log";

        public string[] ExcludedProcesses { get; init; } =
        {
            "explorer",
            "System",
            "SearchProtocolHost",
            "SearchIndexer"
        };

        public static AppSettings CreateDefault()
        {
            return new AppSettings();
        }
    }
}