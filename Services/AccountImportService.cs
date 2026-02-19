using MailArchiver.Data;
using MailArchiver.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Concurrent;

namespace MailArchiver.Services
{
    public class AccountImportService : BackgroundService, IAccountImportService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<AccountImportService> _logger;
        private readonly ConcurrentQueue<AccountImportJob> _jobQueue = new();
        private readonly ConcurrentDictionary<string, AccountImportJob> _allJobs = new();
        private readonly Timer _cleanupTimer;
        private CancellationTokenSource? _currentJobCancellation;
        private readonly Random _random = new();

        public AccountImportService(IServiceProvider serviceProvider, ILogger<AccountImportService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;

            _cleanupTimer = new Timer(
                callback: _ => CleanupOldJobs(),
                state: null,
                dueTime: TimeSpan.FromHours(24),
                period: TimeSpan.FromHours(24)
            );
        }

        public string QueueImport(AccountImportJob job)
        {
            job.Status = AccountImportJobStatus.Queued;
            _allJobs[job.JobId] = job;
            _jobQueue.Enqueue(job);
            _logger.LogInformation("Queued account import job {JobId} with {Count} accounts",
                job.JobId, job.TotalAccounts);
            return job.JobId;
        }

        public AccountImportJob? GetJob(string jobId)
        {
            return _allJobs.TryGetValue(jobId, out var job) ? job : null;
        }

        public List<AccountImportJob> GetActiveJobs()
        {
            return _allJobs.Values
                .Where(j => j.Status == AccountImportJobStatus.Queued || j.Status == AccountImportJobStatus.Running)
                .OrderBy(j => j.Created)
                .ToList();
        }

        public List<AccountImportJob> GetAllJobs()
        {
            return _allJobs.Values
                .OrderByDescending(j => j.Status == AccountImportJobStatus.Running || j.Status == AccountImportJobStatus.Queued)
                .ThenByDescending(j => j.Created)
                .ToList();
        }

        public bool CancelJob(string jobId)
        {
            if (_allJobs.TryGetValue(jobId, out var job))
            {
                if (job.Status == AccountImportJobStatus.Queued)
                {
                    job.Status = AccountImportJobStatus.Cancelled;
                    job.Completed = DateTime.UtcNow;
                    _logger.LogInformation("Cancelled queued account import job {JobId}", jobId);
                    return true;
                }
                else if (job.Status == AccountImportJobStatus.Running)
                {
                    job.Status = AccountImportJobStatus.Cancelled;
                    _currentJobCancellation?.Cancel();
                    _logger.LogInformation("Requested cancellation of running account import job {JobId}", jobId);
                    return true;
                }
            }
            return false;
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Account Import Background Service is starting.");
            return base.StartAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Account Import Background Service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (_jobQueue.TryDequeue(out var job))
                    {
                        if (job.Status == AccountImportJobStatus.Cancelled)
                        {
                            _logger.LogInformation("Skipping cancelled account import job {JobId}", job.JobId);
                            continue;
                        }

                        await ProcessJob(job, stoppingToken);
                    }
                    else
                    {
                        await Task.Delay(100, stoppingToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("Account Import Background Service stopping");
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in Account Import Background Service");
                    await Task.Delay(1000, stoppingToken);
                }
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Account Import Background Service is stopping.");
            return base.StopAsync(cancellationToken);
        }

        private async Task ProcessJob(AccountImportJob job, CancellationToken stoppingToken)
        {
            _currentJobCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var cancellationToken = _currentJobCancellation.Token;

            try
            {
                job.Status = AccountImportJobStatus.Running;
                job.Started = DateTime.UtcNow;

                _logger.LogInformation("Starting account import job {JobId} with {Count} accounts",
                    job.JobId, job.TotalAccounts);

                using var scope = _serviceProvider.CreateScope();
                var context = scope.ServiceProvider.GetRequiredService<MailArchiverDbContext>();

                foreach (var entry in job.Accounts)
                {
                    if (cancellationToken.IsCancellationRequested || job.Status == AccountImportJobStatus.Cancelled)
                    {
                        break;
                    }

                    job.CurrentAccountEmail = entry.Email;

                    try
                    {
                        // Check if an account with this email already exists
                        var existingAccount = await context.MailAccounts
                            .FirstOrDefaultAsync(a => a.EmailAddress == entry.Email, cancellationToken);

                        if (existingAccount != null)
                        {
                            job.SkippedCount++;
                            job.ProcessedAccounts++;
                            job.Results.Add(new AccountImportResult
                            {
                                Email = entry.Email,
                                Success = false,
                                ErrorMessage = "Account with this email already exists"
                            });
                            _logger.LogInformation("Skipped account {Email} - already exists", entry.Email);
                        }
                        else
                        {
                            var account = new MailAccount
                            {
                                Name = entry.Email,
                                EmailAddress = entry.Email,
                                ImapServer = entry.Server,
                                ImapPort = entry.Port,
                                Username = entry.Email,
                                Password = entry.Password,
                                UseSSL = true,
                                IsEnabled = true,
                                Provider = ProviderType.IMAP,
                                ExcludedFolders = string.Empty,
                                LastSync = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                            };

                            context.MailAccounts.Add(account);
                            await context.SaveChangesAsync(cancellationToken);

                            job.SuccessCount++;
                            job.ProcessedAccounts++;
                            job.Results.Add(new AccountImportResult
                            {
                                Email = entry.Email,
                                Success = true
                            });
                            _logger.LogInformation("Successfully imported account {Email}", entry.Email);
                        }
                    }
                    catch (Exception ex)
                    {
                        job.FailedCount++;
                        job.ProcessedAccounts++;
                        job.Results.Add(new AccountImportResult
                        {
                            Email = entry.Email,
                            Success = false,
                            ErrorMessage = ex.Message
                        });
                        _logger.LogError(ex, "Failed to import account {Email}", entry.Email);
                    }

                    // Wait 1-2 seconds between accounts as per requirement
                    if (job.ProcessedAccounts < job.TotalAccounts && !cancellationToken.IsCancellationRequested)
                    {
                        var delay = _random.Next(1000, 2001);
                        await Task.Delay(delay, cancellationToken);
                    }
                }

                if (job.Status != AccountImportJobStatus.Cancelled)
                {
                    job.Status = job.FailedCount > 0
                        ? AccountImportJobStatus.CompletedWithErrors
                        : AccountImportJobStatus.Completed;
                    job.Completed = DateTime.UtcNow;
                    _logger.LogInformation("Completed account import job {JobId}. Success: {Success}, Failed: {Failed}, Skipped: {Skipped}",
                        job.JobId, job.SuccessCount, job.FailedCount, job.SkippedCount);
                }
            }
            catch (OperationCanceledException)
            {
                job.Status = AccountImportJobStatus.Cancelled;
                job.Completed = DateTime.UtcNow;
                _logger.LogInformation("Account import job {JobId} was cancelled", job.JobId);
            }
            catch (Exception ex)
            {
                job.Status = AccountImportJobStatus.Failed;
                job.ErrorMessage = ex.Message;
                job.Completed = DateTime.UtcNow;
                _logger.LogError(ex, "Account import job {JobId} failed", job.JobId);
            }
            finally
            {
                job.CurrentAccountEmail = null;
                _currentJobCancellation?.Dispose();
                _currentJobCancellation = null;
            }
        }

        private void CleanupOldJobs()
        {
            var cutoffTime = DateTime.UtcNow.AddDays(-7);
            var toRemove = _allJobs.Values
                .Where(j => j.Completed.HasValue && j.Completed < cutoffTime)
                .ToList();

            foreach (var job in toRemove)
            {
                _allJobs.TryRemove(job.JobId, out _);
            }

            if (toRemove.Any())
            {
                _logger.LogInformation("Cleaned up {Count} old account import jobs", toRemove.Count);
            }
        }
    }
}
