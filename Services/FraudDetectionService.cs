using MailArchiver.Models;
using System.Text.RegularExpressions;

namespace MailArchiver.Services
{
    /// <summary>
    /// Service for detecting fraudulent and suspicious emails.
    /// Method 1: Checks if the sender address is forged (From header mismatch with actual sending infrastructure).
    /// Method 2: Checks if the email content contains suspicious words or patterns.
    /// </summary>
    public class FraudDetectionService
    {
        private readonly ILogger<FraudDetectionService> _logger;

        // Suspicious words/phrases commonly found in phishing/scam emails
        private static readonly string[] SuspiciousPatterns = new[]
        {
            "verify your account",
            "confirm your identity",
            "click here immediately",
            "act now",
            "urgent action required",
            "your account has been compromised",
            "your account will be suspended",
            "your account will be closed",
            "update your payment",
            "update your billing",
            "unusual activity",
            "unauthorized access",
            "reset your password immediately",
            "lottery winner",
            "you have won",
            "claim your prize",
            "nigerian prince",
            "wire transfer",
            "send money",
            "western union",
            "moneygram",
            "bitcoin payment required",
            "cryptocurrency payment",
            "gift card payment",
            "social security number",
            "bank account details",
            "credit card information",
            "password expired",
            "mailbox full",
            "storage limit exceeded",
            "dear valued customer",
            "dear account holder",
            "this is not a scam",
            "100% guaranteed",
            "risk free",
            "no obligation",
            "free money",
            "make money fast",
            "double your income",
            "financial freedom",
            "work from home opportunity",
            "congratulations you have been selected",
            "your package could not be delivered",
            "delivery attempt failed",
            "invoice attached",
            "overdue payment",
            "legal action will be taken",
            "law enforcement",
            "irs notification",
            "tax refund",
            "suspended account"
        };

        // Well-known domains commonly spoofed in fraud emails
        private static readonly string[] HighValueDomains = new[]
        {
            "apple.com",
            "google.com",
            "microsoft.com",
            "amazon.com",
            "paypal.com",
            "netflix.com",
            "facebook.com",
            "instagram.com",
            "twitter.com",
            "linkedin.com",
            "chase.com",
            "bankofamerica.com",
            "wellsfargo.com",
            "citibank.com",
            "usps.com",
            "fedex.com",
            "ups.com",
            "dhl.com",
            "irs.gov",
            "gov.uk",
            "hmrc.gov.uk"
        };

        public FraudDetectionService(ILogger<FraudDetectionService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Analyzes an email and returns its fraud classification and details.
        /// </summary>
        public (FraudClassification Classification, string? Details) AnalyzeEmail(
            string from, string subject, string body, string? rawHeaders)
        {
            var reasons = new List<string>();

            // Method 1: Check for forged sender (fraud detection)
            var (forgeryReasons, authFailReasons) = CheckForgedSender(from, rawHeaders);

            // Method 2: Check for suspicious content
            var suspiciousReasons = CheckSuspiciousContent(from, subject, body);

            // Classification logic:
            // Fraud = domain forgery indicators (Return-Path/envelope mismatch) combined with auth failures
            // Suspicious = auth failures only, or suspicious content patterns
            // Normal = everything else
            if (forgeryReasons.Any())
            {
                reasons.AddRange(forgeryReasons);
                reasons.AddRange(authFailReasons);
                var details = string.Join("; ", reasons);
                _logger.LogInformation("Email from {From} classified as Fraud: {Details}", from, details);
                return (FraudClassification.Fraud, details);
            }

            if (authFailReasons.Any() || suspiciousReasons.Any())
            {
                reasons.AddRange(authFailReasons);
                reasons.AddRange(suspiciousReasons);
                var details = string.Join("; ", reasons);
                _logger.LogInformation("Email from {From} classified as Suspicious: {Details}", from, details);
                return (FraudClassification.Suspicious, details);
            }

            return (FraudClassification.Normal, null);
        }

        /// <summary>
        /// Method 1: Detects if the sender address is forged by comparing the From header
        /// with actual sending infrastructure information from raw headers.
        /// Returns two lists: forgery indicators (domain mismatches) and authentication failures.
        /// </summary>
        private (List<string> ForgeryReasons, List<string> AuthFailReasons) CheckForgedSender(string from, string? rawHeaders)
        {
            var forgeryReasons = new List<string>();
            var authFailReasons = new List<string>();

            if (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(rawHeaders))
                return (forgeryReasons, authFailReasons);

            var fromDomain = ExtractDomain(from);
            if (string.IsNullOrEmpty(fromDomain))
                return (forgeryReasons, authFailReasons);

            // Check Return-Path mismatch (strong forgery indicator)
            var returnPathDomain = ExtractHeaderDomain(rawHeaders, @"Return-Path:\s*<([^>]+)>");
            if (!string.IsNullOrEmpty(returnPathDomain) &&
                !DomainsMatch(fromDomain, returnPathDomain))
            {
                forgeryReasons.Add($"Return-Path domain mismatch: From={fromDomain}, Return-Path={returnPathDomain}");
            }

            // Check envelope-from / smtp.mailfrom in Authentication-Results (strong forgery indicator)
            var smtpMailFromDomain = ExtractHeaderDomain(rawHeaders, @"smtp\.mailfrom=([^\s;]+)");
            if (!string.IsNullOrEmpty(smtpMailFromDomain) &&
                !DomainsMatch(fromDomain, smtpMailFromDomain))
            {
                forgeryReasons.Add($"SMTP envelope sender mismatch: From={fromDomain}, smtp.mailfrom={smtpMailFromDomain}");
            }

            // Check SPF hard fail only (softfail is common for legitimate emails like mailing lists)
            if (Regex.IsMatch(rawHeaders, @"spf=fail\b", RegexOptions.IgnoreCase))
            {
                authFailReasons.Add("SPF authentication failed");
            }

            // Check DKIM hard fail only (temperror is a transient DNS issue, not fraud)
            if (Regex.IsMatch(rawHeaders, @"dkim=fail\b", RegexOptions.IgnoreCase))
            {
                authFailReasons.Add("DKIM authentication failed");
            }

            // Check DMARC hard fail only
            if (Regex.IsMatch(rawHeaders, @"dmarc=fail\b", RegexOptions.IgnoreCase))
            {
                authFailReasons.Add("DMARC authentication failed");
            }

            // Check if From claims to be from a high-value domain but headers indicate otherwise
            if (IsHighValueDomain(fromDomain))
            {
                // For high-value domains, any forgery indicator is very suspicious
                if (forgeryReasons.Any())
                {
                    forgeryReasons.Insert(0, $"High-value domain impersonation detected ({fromDomain})");
                }
            }

            return (forgeryReasons, authFailReasons);
        }

        /// <summary>
        /// Method 2: Detects suspicious email content by checking for known phishing patterns,
        /// suspicious words, and other indicators.
        /// </summary>
        private List<string> CheckSuspiciousContent(string from, string subject, string body)
        {
            var reasons = new List<string>();
            var combinedText = $"{subject} {body}".ToLowerInvariant();

            // Check for suspicious patterns in content
            var matchedPatterns = new List<string>();
            foreach (var pattern in SuspiciousPatterns)
            {
                if (combinedText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matchedPatterns.Add(pattern);
                }
            }

            // Need at least 2 suspicious pattern matches to classify as suspicious
            if (matchedPatterns.Count >= 2)
            {
                reasons.Add($"Multiple suspicious phrases detected: {string.Join(", ", matchedPatterns.Take(5))}");
            }

            // Check for excessive urgency indicators
            var urgencyCount = CountUrgencyIndicators(combinedText);
            if (urgencyCount >= 3)
            {
                reasons.Add($"Excessive urgency indicators ({urgencyCount} found)");
            }

            // Check for suspicious URL patterns (IP addresses as URLs, misleading domains)
            if (HasSuspiciousUrls(combinedText))
            {
                reasons.Add("Suspicious URL patterns detected");
            }

            return reasons;
        }

        private int CountUrgencyIndicators(string text)
        {
            var urgencyWords = new[] { "urgent", "immediately", "right now", "asap",
                "expire", "expires", "expired", "limited time", "last chance",
                "final warning", "final notice", "within 24 hours", "within 48 hours" };

            return urgencyWords.Count(w => text.Contains(w, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasSuspiciousUrls(string text)
        {
            // Check for IP-based URLs (common in phishing)
            if (Regex.IsMatch(text, @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                return true;

            // Check for data: URIs (potential data exfiltration)
            if (Regex.IsMatch(text, @"data:text/html", RegexOptions.IgnoreCase))
                return true;

            return false;
        }

        private string? ExtractDomain(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;

            var atIndex = email.LastIndexOf('@');
            if (atIndex < 0 || atIndex >= email.Length - 1)
                return null;

            return email[(atIndex + 1)..].Trim().ToLowerInvariant();
        }

        private string? ExtractHeaderDomain(string rawHeaders, string pattern)
        {
            var match = Regex.Match(rawHeaders, pattern, RegexOptions.IgnoreCase);
            if (!match.Success || match.Groups.Count < 2)
                return null;

            return ExtractDomain(match.Groups[1].Value);
        }

        private bool DomainsMatch(string domain1, string domain2)
        {
            if (string.IsNullOrEmpty(domain1) || string.IsNullOrEmpty(domain2))
                return true; // If we can't determine, don't flag

            // Allow subdomain matching (e.g., mail.example.com matches example.com)
            return domain1.Equals(domain2, StringComparison.OrdinalIgnoreCase) ||
                   domain1.EndsWith("." + domain2, StringComparison.OrdinalIgnoreCase) ||
                   domain2.EndsWith("." + domain1, StringComparison.OrdinalIgnoreCase);
        }

        private bool IsHighValueDomain(string domain)
        {
            return HighValueDomains.Any(d =>
                domain.Equals(d, StringComparison.OrdinalIgnoreCase));
        }
    }
}
