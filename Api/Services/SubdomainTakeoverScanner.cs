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
                        $"DNS failed for {host}: {sex.Message}",
                        "Possibly unclaimed (No DNS)"
                    );
                }

                if (ipAddresses.Length == 0)
                {
                    return CreateVulnerabilityResult(
                        "DNS Subdomain Takeover",
                        "High",
                        $"Subdomain {host} has no DNS records",
                        "No DNS – Possible Takeover"
                    );
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
                        $"Connection failed to {url}: {hex.Message}",
                        "Service unreachable"
                    );
                }

                var content = await response.Content.ReadAsStringAsync();

                foreach (var service in _vulnerableServices)
                {
                    foreach (var sig in service.Signatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            return CreateVulnerabilityResult(
                                $"{service.Name} Takeover",
                                "Critical",
                                $"Subdomain {host} likely vulnerable to {service.Name}",
                                $"Signature match: {sig}"
                            );
                        }
                    }
                }

                return new ScanResult
                {
                    Summary = "Secure",
                    Severity = "None",
                    Details = $"No takeover indicators detected for {host}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan failed for {Url}", url);
                return CreateVulnerabilityResult(
                    "Scan Error",
                    "Unknown",
                    $"Scan error: {ex.Message}",
                    "Scan could not be completed"
                );
            }
        }


        // public async Task<ScanResult> ScanAsync(string url)
        // {
        //     var result = new ScanResult();

        //     try
        //     {
        //         if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        //             throw new ArgumentException($"Invalid URL format: {url}");

        //         var host = uri.Host;
        //         _logger.LogInformation("Scanning subdomain: {Host}", host);

        //         IPAddress[] ipAddresses;
        //         try
        //         {
        //             ipAddresses = await Dns.GetHostAddressesAsync(host);
        //         }
        //         catch (SocketException sex)
        //         {
        //             return CreateVulnerabilityResult(
        //                 "DNS Resolution Failed",
        //                 "High",
        //                 $"DNS lookup failed for {host}: {sex.Message}",
        //                 "Subdomain may be available for takeover");
        //         }

        //         if (ipAddresses.Length == 0)
        //         {
        //             return CreateVulnerabilityResult(
        //                 "DNS Subdomain Takeover",
        //                 "High",
        //                 $"Subdomain {host} has no DNS records",
        //                 "Vulnerable to DNS subdomain takeover");
        //         }

        //         HttpResponseMessage response;
        //         try
        //         {
        //             response = await _httpClient.GetAsync(url);
        //         }
        //         catch (HttpRequestException hex)
        //         {
        //             return CreateVulnerabilityResult(
        //                 "Connection Failed",
        //                 "Medium",
        //                 $"Failed to connect to {url}: {hex.Message}",
        //                 "Potential service misconfiguration");
        //         }

        //         var content = await response.Content.ReadAsStringAsync();

        //         foreach (var service in _vulnerableServices)
        //         {
        //             if (service.Signatures.Any(sig => content.Contains(sig, StringComparison.OrdinalIgnoreCase)))
        //             {
        //                 return CreateVulnerabilityResult(
        //                     $"{service.Name} Takeover",
        //                     "Critical",
        //                     $"Subdomain {host} appears vulnerable to {service.Name} takeover",
        //                     $"Found {service.Name} takeover signature");
        //             }
        //         }

        //         result.Details = $"No vulnerabilities detected for {host}";
        //         result.Summary = "Secure subdomain";
        //         return result;
        //     }
        //     catch (Exception ex)
        //     {
        //         _logger.LogError(ex, "Scan failed for URL: {Url}", url);
        //         result.Details = $"Scan failed: {ex.Message}";
        //         result.Summary = "Scan error occurred";
        //         return result;
        //     }
        // }

        // public async Task<List<SubdomainCheckResult>> CheckSubdomainsAsync(List<string> subdomains)
        // {
        //     var results = new List<SubdomainCheckResult>();

        //     foreach (var sub in subdomains)
        //     {
        //         bool scanned = false;

        //         foreach (var scheme in new[] { "http", "https" })
        //         {
        //             var result = new SubdomainCheckResult
        //             {
        //                 Subdomain = sub
        //             };

        //             try
        //             {
        //                 var url = $"{scheme}://{sub}";
        //                 var uri = new Uri(url);
        //                 var host = uri.Host;

        //                 var ipAddresses = await Dns.GetHostAddressesAsync(host);
        //                 result.Status = ipAddresses.Length > 0 ? "Resolved" : "Did Not Resolve";
        //                 result.IP = ipAddresses.Length > 0 ? ipAddresses[0].ToString() : null;

        //                 if (ipAddresses.Length > 0)
        //                 {
        //                     var scan = await ScanAsync(url);
        //                     result.Summary = scan.Summary;
        //                     result.Severity = scan.Severity;

        //                     results.Add(result);
        //                     scanned = true;
        //                     break; // stop after successful scan
        //                 }
        //             }
        //             catch
        //             {
        //                 result.Status = "Did Not Resolve";
        //                 result.Summary = "Error";
        //                 result.Severity = "Unknown";
        //                 results.Add(result);
        //             }
        //         }

        //         if (!scanned)
        //         {
        //             results.Add(new SubdomainCheckResult
        //             {
        //                 Subdomain = sub,
        //                 Status = "Did Not Resolve",
        //                 Summary = "All protocols failed",
        //                 Severity = "Unknown"
        //             });
        //         }
        //     }

        //     return results;
        // }

        public async Task<List<SubdomainCheckResult>> CheckSubdomainsAsync(List<string> subdomains)
        {
            var results = new List<SubdomainCheckResult>();

            foreach (var sub in subdomains)
            {
                bool scanned = false;

                foreach (var scheme in new[] { "http", "https" })
                {
                    var result = new SubdomainCheckResult
                    {
                        Subdomain = sub
                    };

                    try
                    {
                        var url = $"{scheme}://{sub}";
                        var uri = new Uri(url);
                        var host = uri.Host;

                        IPAddress[] ipAddresses;
                        try
                        {
                            ipAddresses = await Dns.GetHostAddressesAsync(host);
                        }
                        catch (SocketException sex)
                        {
                            result.Status = "DNS Failed";
                            result.Summary = "No DNS – Possible Takeover";
                            result.Severity = "High";
                            result.Message = $"DNS lookup failed: {sex.Message}";
                            results.Add(result);
                            scanned = true;
                            break;
                        }

                        if (ipAddresses.Length == 0)
                        {
                            result.Status = "No DNS";
                            result.Summary = "No DNS records – Possible Takeover";
                            result.Severity = "High";
                            result.Message = "Subdomain has no DNS records.";
                            results.Add(result);
                            scanned = true;
                            break;
                        }

                        result.Status = "Resolved";
                        result.IP = ipAddresses[0].ToString();

                        var scan = await ScanAsync(url);

                        result.Summary = scan.Summary;
                        result.Severity = scan.Severity;
                        result.Message = scan.Details;
                        result.Service = scan.Vulnerability?.VulnerabilityName?.Split(' ')?.FirstOrDefault(); // Ex: "GitHub"

                        results.Add(result);
                        scanned = true;
                        break;
                    }
                    catch (Exception ex)
                    {
                        result.Status = "Error";
                        result.Summary = "Scan Failed";
                        result.Severity = "Unknown";
                        result.Message = $"Exception: {ex.Message}";
                        results.Add(result);
                    }
                }

                if (!scanned)
                {
                    results.Add(new SubdomainCheckResult
                    {
                        Subdomain = sub,
                        Status = "Unreachable",
                        Summary = "All protocols failed",
                        Severity = "Unknown",
                        Message = "Could not connect via HTTP or HTTPS"
                    });
                }
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
        public string Status { get; set; } = ""; // Resolved / Did Not Resolve / Error
        public string? IP { get; set; }
        public string? Summary { get; set; } // "Secure", "Possible Takeover", "Takeover Confirmed", "Error"
        public string? Severity { get; set; } // None / Low / Medium / High / Critical
        public string? Service { get; set; } // GitHub / AWS etc.
        public string? Message { get; set; }
    }


    // public class SubdomainCheckResult
    // {
    //     public string Subdomain { get; set; } = "";
    //     public string Status { get; set; } = "";
    //     public string? IP { get; set; }
    //     public string? Summary { get; set; }
    //     public string? Severity { get; set; }
    // }
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