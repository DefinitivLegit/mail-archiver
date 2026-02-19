using MailArchiver.Models;
using System.Text.RegularExpressions;

namespace MailArchiver.Services
{
    /// <summary>
    /// Service for detecting fraudulent and suspicious emails.
    /// Method 1: Checks if the sender address is forged using authentication results and domain analysis.
    /// Method 2: Checks if the email content contains suspicious patterns using weighted scoring.
    /// </summary>
    public partial class FraudDetectionService
    {
        private readonly ILogger<FraudDetectionService> _logger;

        // High-confidence phishing phrases (weighted by severity)
        private static readonly (string Phrase, int Weight)[] WeightedPhishingPhrases =
        [
            // High weight (3) - strong fraud indicators rarely seen in legitimate email
            ("nigerian prince", 3),
            ("bitcoin payment required", 3),
            ("cryptocurrency payment required", 3),
            ("gift card payment", 3),
            ("send money via western union", 3),
            ("send money via moneygram", 3),
            ("social security number", 3),
            ("bank account details", 3),
            ("credit card information", 3),
            ("this is not a scam", 3),
            ("100% guaranteed", 3),
            ("free money", 3),
            ("make money fast", 3),
            ("double your income", 3),
            ("wire transfer urgently", 3),
            ("lottery winner", 3),
            ("you have won a prize", 3),
            ("claim your prize", 3),
            ("congratulations you have been selected", 3),

            // Medium weight (2) - common in phishing but occasionally in legitimate mail
            ("verify your account immediately", 2),
            ("confirm your identity or your account", 2),
            ("click here immediately", 2),
            ("urgent action required", 2),
            ("your account has been compromised", 2),
            ("your account will be suspended", 2),
            ("your account will be closed", 2),
            ("reset your password immediately", 2),
            ("unauthorized access detected", 2),
            ("legal action will be taken", 2),
            ("law enforcement has been notified", 2),
            ("overdue payment must be settled", 2),

            // Low weight (1) - may appear in legitimate emails; only meaningful in combination
            ("unusual activity", 1),
            ("update your payment", 1),
            ("update your billing", 1),
            ("password expired", 1),
            ("suspended account", 1),
            ("dear valued customer", 1),
            ("dear account holder", 1),
            ("your package could not be delivered", 1),
            ("delivery attempt failed", 1),
            ("tax refund", 1),
        ];

        // Well-known domains commonly spoofed in fraud emails
        private static readonly string[] HighValueDomains =
        [
            "apple.com",
            "icloud.com",
            "google.com",
            "gmail.com",
            "microsoft.com",
            "outlook.com",
            "hotmail.com",
            "live.com",
            "amazon.com",
            "paypal.com",
            "netflix.com",
            "facebook.com",
            "meta.com",
            "instagram.com",
            "twitter.com",
            "x.com",
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
            "hmrc.gov.uk",
        ];

        // Brand names for display-name spoofing detection (brand, expected domain suffixes)
        private static readonly (string Brand, string[] DomainSuffixes)[] BrandDomainMap =
        [
            ("apple", ["apple.com", "icloud.com"]),
            ("icloud", ["apple.com", "icloud.com"]),
            ("google", ["google.com", "gmail.com", "googlemail.com", "youtube.com"]),
            ("gmail", ["google.com", "gmail.com", "googlemail.com"]),
            ("microsoft", ["microsoft.com", "outlook.com", "hotmail.com", "live.com", "office365.com", "office.com"]),
            ("outlook", ["microsoft.com", "outlook.com", "hotmail.com"]),
            ("amazon", ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazonaws.com"]),
            ("paypal", ["paypal.com", "paypal.me"]),
            ("netflix", ["netflix.com"]),
            ("facebook", ["facebook.com", "facebookmail.com", "meta.com"]),
            ("instagram", ["instagram.com", "facebook.com", "facebookmail.com", "meta.com"]),
            ("linkedin", ["linkedin.com", "licdn.com"]),
            ("chase", ["chase.com", "jpmorgan.com"]),
            ("wells fargo", ["wellsfargo.com", "wf.com"]),
            ("bank of america", ["bankofamerica.com", "bofa.com"]),
            ("fedex", ["fedex.com"]),
            ("ups", ["ups.com"]),
            ("dhl", ["dhl.com"]),
            ("usps", ["usps.com", "usps.gov"]),
        ];

        // Known legitimate sending/relay service domains that commonly differ from the From domain.
        // These services send on behalf of other organizations and will have a different Return-Path/smtp.mailfrom.
        private static readonly string[] KnownSendingServiceDomains =
        [
            // Google infrastructure
            "google.com",
            "googlemail.com",
            "gserviceaccount.com",
            // Microsoft infrastructure
            "outlook.com",
            "protection.outlook.com",
            "microsoftonline.com",
            "sharepointonline.com",
            // Email service providers
            "sendgrid.net",
            "sendgrid.com",
            "amazonses.com",
            "mailchimp.com",
            "mandrillapp.com",
            "mailgun.org",
            "mailgun.com",
            "sparkpostmail.com",
            "rsgsv.net",
            "mcsv.net",
            "postmarkapp.com",
            "smtp-relay.sendinblue.com",
            "sendinblue.com",
            "brevo.com",
            "constantcontact.com",
            "ccsend.com",
            "hubspot.com",
            "hubspotemail.net",
            "klaviyo.com",
            "intercom-mail.com",
            "customer.io",
            "mailjet.com",
            "elastic.email",
            // Transactional services
            "stripe.com",
            "shopify.com",
            "squarespace.com",
            "zendesk.com",
            "freshdesk.com",
            "atlassian.net",
            "github.com",
            "gitlab.com",
            "slack.com",
            "zoom.us",
            "docusign.net",
            "twilio.com",
            "auth0.com",
            // Mailing list services
            "googlegroups.com",
            "groups.io",
            "freelists.org",
            "listserv.com",
        ];

        // Suspicious URL shortener domains
        private static readonly string[] UrlShortenerDomains =
        [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
            "buff.ly", "adf.ly", "j.mp", "su.pr", "cutt.ly", "rb.gy",
            "shorturl.at", "tiny.cc",
        ];

        // Suspicious TLDs commonly used in phishing
        private static readonly string[] SuspiciousTlds =
        [
            ".xyz", ".top", ".work", ".click", ".link", ".buzz", ".rest",
            ".surf", ".icu", ".monster", ".casa", ".cyou",
        ];

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

            // Method 1: Check for forged sender (authentication-based fraud detection)
            var forgeryResult = CheckForgedSender(from, rawHeaders);

            // Method 2: Check for suspicious content (content-based scoring)
            var contentResult = CheckSuspiciousContent(from, subject, body);

            // Classification logic:
            // Fraud = DMARC fail, or (domain mismatch + auth failure + not a known sending service),
            //         or high-value domain impersonation with auth failure
            // Suspicious = content score above threshold, or minor auth concerns, or display name spoofing
            // Normal = authentication passes and no concerning content indicators

            if (forgeryResult.IsFraud)
            {
                reasons.AddRange(forgeryResult.Reasons);
                var details = string.Join("; ", reasons);
                _logger.LogInformation("Email from {From} classified as Fraud: {Details}", from, details);
                return (FraudClassification.Fraud, details);
            }

            if (forgeryResult.IsSuspicious || contentResult.IsSuspicious)
            {
                reasons.AddRange(forgeryResult.Reasons);
                reasons.AddRange(contentResult.Reasons);
                var details = string.Join("; ", reasons);
                _logger.LogInformation("Email from {From} classified as Suspicious: {Details}", from, details);
                return (FraudClassification.Suspicious, details);
            }

            return (FraudClassification.Normal, null);
        }

        /// <summary>
        /// Method 1: Detects if the sender address is forged by analyzing authentication results
        /// and domain relationships. Domain mismatches are only treated as forgery when
        /// authentication also fails, since legitimate services commonly use different
        /// Return-Path/smtp.mailfrom domains (e.g., SendGrid, Google infrastructure).
        /// </summary>
        private ForgeryAnalysisResult CheckForgedSender(string from, string? rawHeaders)
        {
            var result = new ForgeryAnalysisResult();

            if (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(rawHeaders))
                return result;

            var fromDomain = ExtractDomain(from);
            if (string.IsNullOrEmpty(fromDomain))
                return result;

            // Parse authentication results from headers
            var authResults = ParseAuthenticationResults(rawHeaders);

            // DMARC fail is the strongest fraud signal - it was designed specifically to detect
            // From-header spoofing by combining SPF and DKIM alignment checks.
            if (authResults.DmarcResult == AuthResult.Fail)
            {
                result.Reasons.Add("DMARC authentication failed (sender domain alignment failure)");

                // Check domain mismatches for additional context
                AddDomainMismatchContext(result, fromDomain, rawHeaders);

                // High-value domain impersonation with DMARC fail is definitive fraud
                if (IsHighValueDomain(fromDomain))
                {
                    result.Reasons.Insert(0, $"High-value domain impersonation detected ({fromDomain})");
                }

                result.IsFraud = true;
                return result;
            }

            // Check for domain mismatches (Return-Path and smtp.mailfrom)
            bool hasReturnPathMismatch = false;
            bool hasSmtpMailFromMismatch = false;
            var returnPathDomain = ExtractHeaderDomain(rawHeaders, @"Return-Path:\s*<([^>]+)>");
            var smtpMailFromDomain = ExtractHeaderDomain(rawHeaders, @"smtp\.mailfrom=([^\s;]+)");

            if (!string.IsNullOrEmpty(returnPathDomain) && !DomainsMatch(fromDomain, returnPathDomain))
            {
                hasReturnPathMismatch = !IsKnownSendingService(returnPathDomain);
            }

            if (!string.IsNullOrEmpty(smtpMailFromDomain) && !DomainsMatch(fromDomain, smtpMailFromDomain))
            {
                hasSmtpMailFromMismatch = !IsKnownSendingService(smtpMailFromDomain);
            }

            bool hasDomainMismatch = hasReturnPathMismatch || hasSmtpMailFromMismatch;

            // Domain mismatch combined with SPF or DKIM failure (but not DMARC fail which is handled above)
            bool hasAuthFailure = authResults.SpfResult == AuthResult.Fail ||
                                  authResults.DkimResult == AuthResult.Fail;

            if (hasDomainMismatch && hasAuthFailure)
            {
                if (hasReturnPathMismatch)
                    result.Reasons.Add($"Return-Path domain mismatch: From={fromDomain}, Return-Path={returnPathDomain}");
                if (hasSmtpMailFromMismatch)
                    result.Reasons.Add($"SMTP envelope sender mismatch: From={fromDomain}, smtp.mailfrom={smtpMailFromDomain}");
                if (authResults.SpfResult == AuthResult.Fail)
                    result.Reasons.Add("SPF authentication failed");
                if (authResults.DkimResult == AuthResult.Fail)
                    result.Reasons.Add("DKIM authentication failed");

                if (IsHighValueDomain(fromDomain))
                {
                    result.Reasons.Insert(0, $"High-value domain impersonation detected ({fromDomain})");
                    result.IsFraud = true;
                }
                else
                {
                    result.IsFraud = true;
                }

                return result;
            }

            // SPF or DKIM failure alone (without domain mismatch) is suspicious but not fraud,
            // as transient issues can cause legitimate failures
            if (hasAuthFailure && !hasDomainMismatch)
            {
                if (authResults.SpfResult == AuthResult.Fail)
                    result.Reasons.Add("SPF authentication failed");
                if (authResults.DkimResult == AuthResult.Fail)
                    result.Reasons.Add("DKIM authentication failed");
                result.IsSuspicious = true;
            }

            // Domain mismatch from unknown sending service with no clear auth pass is suspicious
            if (hasDomainMismatch && authResults.SpfResult != AuthResult.Pass && authResults.DkimResult != AuthResult.Pass)
            {
                if (hasReturnPathMismatch)
                    result.Reasons.Add($"Return-Path domain mismatch from unknown service: From={fromDomain}, Return-Path={returnPathDomain}");
                if (hasSmtpMailFromMismatch)
                    result.Reasons.Add($"SMTP envelope mismatch from unknown service: From={fromDomain}, smtp.mailfrom={smtpMailFromDomain}");
                result.IsSuspicious = true;
            }

            return result;
        }

        /// <summary>
        /// Method 2: Detects suspicious email content using weighted scoring for phishing patterns,
        /// display name spoofing, urgency indicators, and suspicious URL analysis.
        /// </summary>
        private ContentAnalysisResult CheckSuspiciousContent(string from, string subject, string body)
        {
            var result = new ContentAnalysisResult();
            var combinedText = $"{subject} {body}".ToLowerInvariant();
            int score = 0;

            // Check weighted phishing phrases
            var matchedPatterns = new List<string>();
            foreach (var (phrase, weight) in WeightedPhishingPhrases)
            {
                if (combinedText.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                {
                    matchedPatterns.Add(phrase);
                    score += weight;
                }
            }

            if (matchedPatterns.Count > 0)
            {
                result.Reasons.Add($"Phishing phrases detected: {string.Join(", ", matchedPatterns.Take(5))}");
            }

            // Check for display name spoofing (From name contains brand but domain doesn't match)
            var displayNameScore = CheckDisplayNameSpoofing(from);
            if (displayNameScore.Score > 0)
            {
                score += displayNameScore.Score;
                result.Reasons.Add(displayNameScore.Reason!);
            }

            // Check for urgency indicators
            var urgencyCount = CountUrgencyIndicators(combinedText);
            if (urgencyCount >= 3)
            {
                score += urgencyCount;
                result.Reasons.Add($"Excessive urgency indicators ({urgencyCount} found)");
            }
            else if (urgencyCount >= 2)
            {
                score += 1;
            }

            // Check for suspicious URL patterns
            var urlAnalysis = AnalyzeUrls(combinedText);
            if (urlAnalysis.Score > 0)
            {
                score += urlAnalysis.Score;
                result.Reasons.AddRange(urlAnalysis.Reasons);
            }

            // Threshold: score >= 4 is suspicious (e.g., one high-weight phrase + urgency,
            // or two medium-weight phrases, or display name spoofing + low-weight phrases)
            result.IsSuspicious = score >= 4;
            result.Score = score;

            return result;
        }

        /// <summary>
        /// Checks if the From display name impersonates a well-known brand while
        /// the actual email domain doesn't belong to that brand.
        /// </summary>
        private (int Score, string? Reason) CheckDisplayNameSpoofing(string from)
        {
            if (string.IsNullOrEmpty(from))
                return (0, null);

            var fromLower = from.ToLowerInvariant();
            var fromDomain = ExtractDomain(from);
            if (string.IsNullOrEmpty(fromDomain))
                return (0, null);

            foreach (var (brand, domainSuffixes) in BrandDomainMap)
            {
                // Check if the From address text (display name portion) contains the brand name
                // but the actual domain doesn't match any expected domain for that brand
                bool nameContainsBrand = fromLower.Contains(brand);
                if (!nameContainsBrand)
                    continue;

                bool domainMatchesBrand = domainSuffixes.Any(d =>
                    fromDomain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                    fromDomain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

                if (!domainMatchesBrand)
                {
                    return (4, $"Display name spoofing: From contains '{brand}' but domain is {fromDomain}");
                }
            }

            return (0, null);
        }

        /// <summary>
        /// Parses SPF, DKIM, and DMARC results from Authentication-Results headers.
        /// </summary>
        private static AuthenticationResults ParseAuthenticationResults(string rawHeaders)
        {
            var results = new AuthenticationResults();

            // SPF results
            if (SpfPassRegex().IsMatch(rawHeaders))
                results.SpfResult = AuthResult.Pass;
            else if (SpfFailRegex().IsMatch(rawHeaders))
                results.SpfResult = AuthResult.Fail;
            else if (SpfSoftfailRegex().IsMatch(rawHeaders))
                results.SpfResult = AuthResult.Softfail;
            else if (SpfNoneRegex().IsMatch(rawHeaders))
                results.SpfResult = AuthResult.None;

            // DKIM results
            if (DkimPassRegex().IsMatch(rawHeaders))
                results.DkimResult = AuthResult.Pass;
            else if (DkimFailRegex().IsMatch(rawHeaders))
                results.DkimResult = AuthResult.Fail;
            else if (DkimNoneRegex().IsMatch(rawHeaders))
                results.DkimResult = AuthResult.None;

            // DMARC results
            if (DmarcPassRegex().IsMatch(rawHeaders))
                results.DmarcResult = AuthResult.Pass;
            else if (DmarcFailRegex().IsMatch(rawHeaders))
                results.DmarcResult = AuthResult.Fail;
            else if (DmarcNoneRegex().IsMatch(rawHeaders))
                results.DmarcResult = AuthResult.None;

            return results;
        }

        private int CountUrgencyIndicators(string text)
        {
            string[] urgencyWords =
            [
                "urgent", "immediately", "right now", "asap",
                "expire", "expires", "expired", "limited time", "last chance",
                "final warning", "final notice", "within 24 hours", "within 48 hours",
                "act now", "respond immediately", "time sensitive", "don't delay",
            ];

            return urgencyWords.Count(w => text.Contains(w, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Analyzes URLs found in the email text for suspicious patterns including
        /// IP-based URLs, data: URIs, URL shorteners, suspicious TLDs, and lookalike domains.
        /// </summary>
        private static UrlAnalysisResult AnalyzeUrls(string text)
        {
            var result = new UrlAnalysisResult();

            // Check for IP-based URLs (common in phishing)
            if (IpUrlRegex().IsMatch(text))
            {
                result.Score += 3;
                result.Reasons.Add("IP-based URL detected (common in phishing)");
            }

            // Check for data: URIs (potential credential phishing/exfiltration)
            if (DataUriRegex().IsMatch(text))
            {
                result.Score += 3;
                result.Reasons.Add("Suspicious data: URI detected");
            }

            // Check for URL shortener usage
            foreach (var shortener in UrlShortenerDomains)
            {
                if (text.Contains(shortener, StringComparison.OrdinalIgnoreCase))
                {
                    result.Score += 2;
                    result.Reasons.Add($"URL shortener detected ({shortener})");
                    break;
                }
            }

            // Check for suspicious TLDs in URLs
            var urlMatches = UrlRegex().Matches(text);
            foreach (Match match in urlMatches)
            {
                var url = match.Value.ToLowerInvariant();
                foreach (var tld in SuspiciousTlds)
                {
                    // Check if the URL host ends with a suspicious TLD (before any path)
                    var hostPart = ExtractHostFromUrl(url);
                    if (hostPart != null && hostPart.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Score += 2;
                        result.Reasons.Add($"Suspicious TLD in URL ({tld})");
                        break;
                    }
                }
            }

            // Check for lookalike domains in URLs targeting high-value brands
            foreach (Match match in urlMatches)
            {
                var host = ExtractHostFromUrl(match.Value.ToLowerInvariant());
                if (host != null && IsLookalikeDomain(host))
                {
                    result.Score += 3;
                    result.Reasons.Add($"Possible lookalike domain in URL: {host}");
                    break;
                }
            }

            return result;
        }

        /// <summary>
        /// Detects domains that try to impersonate high-value brands using common typosquatting
        /// techniques: character substitution, extra/missing characters, and hyphenation.
        /// </summary>
        private static bool IsLookalikeDomain(string host)
        {
            // Common character substitutions used in typosquatting.
            // Homoglyph attacks use visually similar characters: l↔1↔I, o↔0, rn↔m, etc.
            (string Original, string[] Fakes)[] brandVariants =
            [
                ("paypal", ["paypa1", "paypai", "paypaI", "paipal", "paypol", "payp4l", "paypal-"]),
                ("apple", ["app1e", "appie", "appIe", "aple", "appl3", "apple-"]),
                ("google", ["g00gle", "go0gle", "googie", "googIe", "gogle", "g0ogle", "google-"]),
                ("microsoft", ["micr0soft", "microsft", "rnicrosoft", "mlcrosoft", "microsoft-"]),
                ("amazon", ["amaz0n", "arnazon", "amazom", "armazom", "amazon-"]),
                ("netflix", ["netf1ix", "netfllx", "netfl1x", "nettflix", "netflix-"]),
                ("facebook", ["faceb00k", "facebo0k", "faceboak", "facebook-"]),
                ("linkedin", ["1inkedin", "linkedln", "llnkedin", "linkedin-"]),
                ("chase", ["chas3", "chasse", "chase-"]),
                ("wellsfargo", ["we11sfargo", "wellsfarg0", "wellsfargo-"]),
            ];

            foreach (var (brand, fakes) in brandVariants)
            {
                foreach (var fake in fakes)
                {
                    if (host.Contains(fake, StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                // Check for brand name with suspicious TLD (e.g., paypal.xyz)
                foreach (var tld in SuspiciousTlds)
                {
                    if (host.Equals(brand + "." + tld.TrimStart('.'), StringComparison.OrdinalIgnoreCase) ||
                        host.EndsWith("." + brand + tld, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }

        private static string? ExtractHostFromUrl(string url)
        {
            // Remove scheme
            var idx = url.IndexOf("://", StringComparison.Ordinal);
            if (idx < 0) return null;
            var rest = url[(idx + 3)..];
            // Take everything before the first / or end
            var slashIdx = rest.IndexOf('/');
            var host = slashIdx >= 0 ? rest[..slashIdx] : rest;
            // Remove port
            var colonIdx = host.LastIndexOf(':');
            if (colonIdx > 0) host = host[..colonIdx];
            // Remove userinfo (user@)
            var atIdx = host.IndexOf('@');
            if (atIdx >= 0) host = host[(atIdx + 1)..];
            return host.Length > 0 ? host : null;
        }

        private void AddDomainMismatchContext(ForgeryAnalysisResult result, string fromDomain, string rawHeaders)
        {
            var returnPathDomain = ExtractHeaderDomain(rawHeaders, @"Return-Path:\s*<([^>]+)>");
            if (!string.IsNullOrEmpty(returnPathDomain) && !DomainsMatch(fromDomain, returnPathDomain))
            {
                result.Reasons.Add($"Return-Path domain mismatch: From={fromDomain}, Return-Path={returnPathDomain}");
            }

            var smtpMailFromDomain = ExtractHeaderDomain(rawHeaders, @"smtp\.mailfrom=([^\s;]+)");
            if (!string.IsNullOrEmpty(smtpMailFromDomain) && !DomainsMatch(fromDomain, smtpMailFromDomain))
            {
                result.Reasons.Add($"SMTP envelope sender mismatch: From={fromDomain}, smtp.mailfrom={smtpMailFromDomain}");
            }
        }

        private static string? ExtractDomain(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;

            // Handle "Display Name <email@domain.com>" format
            var angleStart = email.IndexOf('<');
            var angleEnd = email.IndexOf('>');
            if (angleStart >= 0 && angleEnd > angleStart)
            {
                email = email[(angleStart + 1)..angleEnd];
            }

            var atIndex = email.LastIndexOf('@');
            if (atIndex < 0 || atIndex >= email.Length - 1)
                return null;

            return email[(atIndex + 1)..].Trim().TrimEnd('>').ToLowerInvariant();
        }

        private static string? ExtractHeaderDomain(string rawHeaders, string pattern)
        {
            var match = Regex.Match(rawHeaders, pattern, RegexOptions.IgnoreCase);
            if (!match.Success || match.Groups.Count < 2)
                return null;

            return ExtractDomain(match.Groups[1].Value);
        }

        private static bool DomainsMatch(string domain1, string domain2)
        {
            if (string.IsNullOrEmpty(domain1) || string.IsNullOrEmpty(domain2))
                return true; // If we can't determine, don't flag

            // Exact match
            if (domain1.Equals(domain2, StringComparison.OrdinalIgnoreCase))
                return true;

            // Allow subdomain matching (e.g., mail.example.com matches example.com)
            if (domain1.EndsWith("." + domain2, StringComparison.OrdinalIgnoreCase) ||
                domain2.EndsWith("." + domain1, StringComparison.OrdinalIgnoreCase))
                return true;

            // Allow matching on organizational domain (e.g., gmail.com and google.com are related)
            var org1 = GetOrganizationalDomain(domain1);
            var org2 = GetOrganizationalDomain(domain2);
            if (!string.IsNullOrEmpty(org1) && org1.Equals(org2, StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        /// <summary>
        /// Maps well-known related domains to their organizational parent to avoid
        /// false positives when, e.g., gmail.com sends via google.com infrastructure.
        /// </summary>
        private static string? GetOrganizationalDomain(string domain)
        {
            // Map well-known domain families
            string[][] domainFamilies =
            [
                ["google.com", "gmail.com", "googlemail.com", "youtube.com", "googlegroups.com"],
                ["microsoft.com", "outlook.com", "hotmail.com", "live.com", "office365.com", "office.com", "microsoftonline.com", "sharepointonline.com"],
                ["apple.com", "icloud.com", "me.com", "mac.com"],
                ["facebook.com", "facebookmail.com", "instagram.com", "meta.com"],
                ["amazon.com", "amazonaws.com", "amazonses.com"],
                ["yahoo.com", "yahoomail.com", "ymail.com", "aol.com"],
            ];

            foreach (var family in domainFamilies)
            {
                // Check if the domain (or its parent) belongs to this family
                if (family.Any(d => domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                    domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)))
                {
                    return family[0]; // Return the canonical/primary domain
                }
            }

            return null;
        }

        private static bool IsKnownSendingService(string domain)
        {
            return KnownSendingServiceDomains.Any(d =>
                domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsHighValueDomain(string domain)
        {
            return HighValueDomains.Any(d =>
                domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        }

        // Source-generated regexes for authentication result parsing
        [GeneratedRegex(@"spf=pass\b", RegexOptions.IgnoreCase)]
        private static partial Regex SpfPassRegex();
        [GeneratedRegex(@"spf=fail\b", RegexOptions.IgnoreCase)]
        private static partial Regex SpfFailRegex();
        [GeneratedRegex(@"spf=softfail\b", RegexOptions.IgnoreCase)]
        private static partial Regex SpfSoftfailRegex();
        [GeneratedRegex(@"spf=none\b", RegexOptions.IgnoreCase)]
        private static partial Regex SpfNoneRegex();
        [GeneratedRegex(@"dkim=pass\b", RegexOptions.IgnoreCase)]
        private static partial Regex DkimPassRegex();
        [GeneratedRegex(@"dkim=fail\b", RegexOptions.IgnoreCase)]
        private static partial Regex DkimFailRegex();
        [GeneratedRegex(@"dkim=none\b", RegexOptions.IgnoreCase)]
        private static partial Regex DkimNoneRegex();
        [GeneratedRegex(@"dmarc=pass\b", RegexOptions.IgnoreCase)]
        private static partial Regex DmarcPassRegex();
        [GeneratedRegex(@"dmarc=fail\b", RegexOptions.IgnoreCase)]
        private static partial Regex DmarcFailRegex();
        [GeneratedRegex(@"dmarc=none\b", RegexOptions.IgnoreCase)]
        private static partial Regex DmarcNoneRegex();
        [GeneratedRegex(@"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", RegexOptions.IgnoreCase)]
        private static partial Regex IpUrlRegex();
        [GeneratedRegex(@"data:(text/html|application/)", RegexOptions.IgnoreCase)]
        private static partial Regex DataUriRegex();
        [GeneratedRegex(@"https?://[^\s""'<>]+", RegexOptions.IgnoreCase)]
        private static partial Regex UrlRegex();

        // Internal types for analysis results
        private sealed class ForgeryAnalysisResult
        {
            public bool IsFraud { get; set; }
            public bool IsSuspicious { get; set; }
            public List<string> Reasons { get; } = [];
        }

        private sealed class ContentAnalysisResult
        {
            public bool IsSuspicious { get; set; }
            public int Score { get; set; }
            public List<string> Reasons { get; } = [];
        }

        private sealed class UrlAnalysisResult
        {
            public int Score { get; set; }
            public List<string> Reasons { get; } = [];
        }

        private enum AuthResult
        {
            Unknown,
            Pass,
            Fail,
            Softfail,
            None,
        }

        private sealed class AuthenticationResults
        {
            public AuthResult SpfResult { get; set; } = AuthResult.Unknown;
            public AuthResult DkimResult { get; set; } = AuthResult.Unknown;
            public AuthResult DmarcResult { get; set; } = AuthResult.Unknown;
        }
    }
}
