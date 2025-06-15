// =============================
// 2. SubdomainTakeoverScanner.cs
// =============================
using System.Net;
using Api.Models;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Api.Services.Scanners
{
    public class SubdomainTakeoverScanner
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<SubdomainTakeoverScanner> _logger;
        private readonly List<SubdomainTakeoverService> _vulnerableServices;

        public SubdomainTakeoverScanner(HttpClient httpClient, ILogger<SubdomainTakeoverScanner> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
            _vulnerableServices = GetVulnerableServices();
        }

        private List<SubdomainTakeoverService> GetVulnerableServices()
        {
            return new List<SubdomainTakeoverService>
            {
                new("AWS S3", new[] {"NoSuchBucket", "The specified bucket does not exist"}),
                new("GitHub Pages", new[] {"There isn't a GitHub Pages site here"}),
                new("Heroku", new[] {"No such app", "herokucdn.com/error-pages/no-such-app.html"}),
                new("Shopify", new[] {"Sorry, this shop is currently unavailable"}),
                new("Fastly", new[] {"Fastly error: unknown domain"}),
                new("Azure Blob Storage", new[] {"ErrorCode: ContainerNotFound", "The specified container does not exist"}),
                new("Google Cloud Storage", new[] {"NoSuchBucket", "The specified bucket does not exist"})
            };
        }

        public async Task<ScanResult> ScanAsync(string url)
        {
            var result = new ScanResult();

            try
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    throw new ArgumentException($"Invalid URL format: {url}");

                var host = uri.Host;
                _logger.LogInformation("Scanning subdomain: {Host}", host);

                IPAddress[] ipAddresses;
                try
                {
                    ipAddresses = await Dns.GetHostAddressesAsync(host);
                }
                catch (SocketException sex)
                {
                    return CreateVulnerabilityResult(
                        "DNS Resolution Failed",
                        "High",
                        $"DNS lookup failed for {host}: {sex.Message}",
                        "Subdomain may be available for takeover");
                }

                if (ipAddresses.Length == 0)
                {
                    return CreateVulnerabilityResult(
                        "DNS Subdomain Takeover",
                        "High",
                        $"Subdomain {host} has no DNS records",
                        "Vulnerable to DNS subdomain takeover");
                }

                HttpResponseMessage response;
                try
                {
                    response = await _httpClient.GetAsync(url);
                }
                catch (HttpRequestException hex)
                {
                    return CreateVulnerabilityResult(
                        "Connection Failed",
                        "Medium",
                        $"Failed to connect to {url}: {hex.Message}",
                        "Potential service misconfiguration");
                }

                var content = await response.Content.ReadAsStringAsync();

                foreach (var service in _vulnerableServices)
                {
                    if (service.Signatures.Any(sig => content.Contains(sig, StringComparison.OrdinalIgnoreCase)))
                    {
                        return CreateVulnerabilityResult(
                            $"{service.Name} Takeover",
                            "Critical",
                            $"Subdomain {host} appears vulnerable to {service.Name} takeover",
                            $"Found {service.Name} takeover signature");
                    }
                }

                result.Details = $"No vulnerabilities detected for {host}";
                result.Summary = "Secure subdomain";
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan failed for URL: {Url}", url);
                result.Details = $"Scan failed: {ex.Message}";
                result.Summary = "Scan error occurred";
                return result;
            }
        }

        public async Task<List<SubdomainCheckResult>> CheckSubdomainsAsync(List<string> subdomains)
        {
            var results = new List<SubdomainCheckResult>();

            foreach (var sub in subdomains)
            {
                var result = new SubdomainCheckResult
                {
                    Subdomain = sub
                };

                try
                {
                    var url = sub.StartsWith("http") ? sub : $"http://{sub}";
                    var uri = new Uri(url);
                    var host = uri.Host;

                    var ipAddresses = await Dns.GetHostAddressesAsync(host);
                    result.Status = ipAddresses.Length > 0 ? "Resolved" : "Did Not Resolve";
                    result.IP = ipAddresses.Length > 0 ? ipAddresses[0].ToString() : null;

                    if (ipAddresses.Length > 0)
                    {
                        var scan = await ScanAsync(url);
                        result.Summary = scan.Summary;
                        result.Severity = scan.Severity;
                    }
                }
                catch (Exception ex)
                {
                    result.Status = "Did Not Resolve";
                    result.Summary = "Error";
                    result.Severity = "Unknown";
                }

                results.Add(result);
            }

            return results;
        }

        private ScanResult CreateVulnerabilityResult(string name, string severity, string details, string summary)
        {
            return new ScanResult
            {
                Vulnerability = new Vulnerability
                {
                    VulnerabilityName = name,
                    Description = summary,
                    CreatedAt = DateTime.UtcNow
                },
                Severity = severity,
                Details = details,
                Summary = summary
            };
        }
    }

    public record SubdomainTakeoverService(string Name, string[] Signatures);

    public class SubdomainCheckResult
    {
        public string Subdomain { get; set; } = "";
        public string Status { get; set; } = "";
        public string? IP { get; set; }
        public string? Summary { get; set; }
        public string? Severity { get; set; }
    }
}



// using System.Net;
// using Api.Models;
// using System.Net.Sockets;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Logging;


// namespace Api.Services.Scanners
// {
//     public class SubdomainTakeoverScanner
//     {
//         private readonly HttpClient _httpClient;
//         private readonly ILogger<SubdomainTakeoverScanner> _logger;
//         private readonly List<SubdomainTakeoverService> _vulnerableServices;

//         // Add ILogger to constructor parameters
//         public SubdomainTakeoverScanner(
//             HttpClient httpClient,
//             ILogger<SubdomainTakeoverScanner> logger)
//         {
//             _httpClient = httpClient;
//             _logger = logger;
//             _vulnerableServices = GetVulnerableServices();
//         }

//         private List<SubdomainTakeoverService> GetVulnerableServices()
//         {
//             return new List<SubdomainTakeoverService>
//             {
//                 new("AWS S3", ["NoSuchBucket", "The specified bucket does not exist"]),
//                 new("GitHub Pages", ["There isn't a GitHub Pages site here"]),
//                 new("Heroku", ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
//                 new("Shopify", ["Sorry, this shop is currently unavailable"]),
//                 new("Fastly", ["Fastly error: unknown domain"]),
//                 new("Azure Blob Storage", ["ErrorCode: ContainerNotFound", "The specified container does not exist"]),
//                 new("Google Cloud Storage", ["NoSuchBucket", "The specified bucket does not exist"])
//             };
//         }

//         public async Task<ScanResult> ScanAsync(string url)
//         {
//             var result = new ScanResult();
            
//             try
//             {
//                 if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
//                 {
//                     throw new ArgumentException($"Invalid URL format: {url}");
//                 }

//                 var host = uri.Host;
//                 _logger.LogInformation("Scanning subdomain: {Host}", host);

//                 // DNS resolution check
//                 IPAddress[] ipAddresses;
//                 try
//                 {
//                     ipAddresses = await Dns.GetHostAddressesAsync(host);
//                 }
//                 catch (SocketException sex)
//                 {
//                     return CreateVulnerabilityResult(
//                         "DNS Resolution Failed",
//                         "High",
//                         $"DNS lookup failed for {host}: {sex.Message}",
//                         "Subdomain may be available for takeover");
//                 }

//                 if (ipAddresses.Length == 0)
//                 {
//                     return CreateVulnerabilityResult(
//                         "DNS Subdomain Takeover",
//                         "High",
//                         $"Subdomain {host} has no DNS records",
//                         "Vulnerable to DNS subdomain takeover");
//                 }

//                 // HTTP request
//                 HttpResponseMessage response;
//                 try
//                 {
//                     response = await _httpClient.GetAsync(url);
//                 }
//                 catch (HttpRequestException hex)
//                 {
//                     return CreateVulnerabilityResult(
//                         "Connection Failed",
//                         "Medium",
//                         $"Failed to connect to {url}: {hex.Message}",
//                         "Potential service misconfiguration");
//                 }

//                 var content = await response.Content.ReadAsStringAsync();

//                 // Check for known vulnerable services
//                 foreach (var service in _vulnerableServices)
//                 {
//                     if (service.Signatures.Any(sig => content.Contains(sig, StringComparison.OrdinalIgnoreCase)))
//                     {
//                         return CreateVulnerabilityResult(
//                             $"{service.Name} Takeover",
//                             "Critical",
//                             $"Subdomain {host} appears vulnerable to {service.Name} takeover",
//                             $"Found {service.Name} takeover signature");
//                     }
//                 }

//                 result.Details = $"No vulnerabilities detected for {host}";
//                 result.Summary = "Secure subdomain";
//                 return result;
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Scan failed for URL: {Url}", url);
//                 result.Details = $"Scan failed: {ex.Message}";
//                 result.Summary = "Scan error occurred";
//                 return result;
//             }
//         }

//         private ScanResult CreateVulnerabilityResult(string name, string severity, string details, string summary)
//         {
//             return new ScanResult
//             {
//                 Vulnerability = new Vulnerability
//                 {
//                     VulnerabilityName = name,
//                     Description = summary,
//                     CreatedAt = DateTime.UtcNow
//                 },
//                 Severity = severity,
//                 Details = details,
//                 Summary = summary
//             };
//         }
//     }

//     public record SubdomainTakeoverService(string Name, string[] Signatures);
// }