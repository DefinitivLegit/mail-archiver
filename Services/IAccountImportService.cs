using MailArchiver.Models;

namespace MailArchiver.Services
{
    public interface IAccountImportService
    {
        string QueueImport(AccountImportJob job);
        AccountImportJob? GetJob(string jobId);
        List<AccountImportJob> GetActiveJobs();
        List<AccountImportJob> GetAllJobs();
        bool CancelJob(string jobId);
    }
}
