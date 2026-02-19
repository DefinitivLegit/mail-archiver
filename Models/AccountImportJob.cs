namespace MailArchiver.Models
{
    public class AccountImportJob
    {
        public string JobId { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; } = "System";
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime? Started { get; set; }
        public DateTime? Completed { get; set; }
        public AccountImportJobStatus Status { get; set; } = AccountImportJobStatus.Queued;
        public int TotalAccounts { get; set; }
        public int ProcessedAccounts { get; set; }
        public int SuccessCount { get; set; }
        public int FailedCount { get; set; }
        public int SkippedCount { get; set; }
        public string? CurrentAccountEmail { get; set; }
        public string? ErrorMessage { get; set; }
        public List<AccountImportEntry> Accounts { get; set; } = new();
        public List<AccountImportResult> Results { get; set; } = new();
    }

    public class AccountImportEntry
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Server { get; set; } = string.Empty;
        public int Port { get; set; } = 993;
    }

    public class AccountImportResult
    {
        public string Email { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public enum AccountImportJobStatus
    {
        Queued,
        Running,
        Completed,
        CompletedWithErrors,
        Failed,
        Cancelled
    }
}
