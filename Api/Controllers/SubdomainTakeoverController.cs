using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using Microsoft.Extensions.Logging;
using Api.Services;
using System.Net.Http;
using Api.Services.Scanners;
using Api.DTOs;
using System.Collections.Generic;
using iTextSharp.text;
using iTextSharp.text.pdf;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class SubdomainTakeoverController : ControllerBase
    {
        private readonly SubdomainTakeoverScanner _scanner;
        private readonly SubdomainExtractorService _extractor;
        private readonly ApiContext _context;
        private readonly ILogger<SubdomainTakeoverController> _logger;

        private readonly IHttpClientFactory _clientFactory;
        private static List<SubdomainCheckResult> _lastScanResults = new();

        public SubdomainTakeoverController(
            SubdomainTakeoverScanner scanner,
            SubdomainExtractorService extractor,
            ApiContext context,
            ILogger<SubdomainTakeoverController> logger,
            IHttpClientFactory clientFactory)
        {
            _scanner = scanner;
            _extractor = extractor;
            _context = context;
            _logger = logger;
            _clientFactory = clientFactory;
        }




        [HttpPost("scan-domain")]
        public async Task<IActionResult> ScanDomain([FromBody] string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return BadRequest("Domain is required.");

            var subdomains = await _extractor.GetSubdomainsAsync(domain);

            if (subdomains.Count == 0)
                return NotFound("No subdomains found for this domain.");

            var scanRequest = new ScanRequest
            {
                UserId = User.FindFirstValue(ClaimTypes.NameIdentifier),
                Status = "In Progress",
                StartedAt = DateTime.UtcNow,
                Website = new Website
                {
                    Url = domain,
                    CreatedAt = DateTime.UtcNow,
                    UserId = User.FindFirstValue(ClaimTypes.NameIdentifier)
                }
            };

            _context.ScanRequests.Add(scanRequest);
            await _context.SaveChangesAsync();

            var results = await _scanner.CheckSubdomainsAsync(subdomains);
            _lastScanResults = results;

            var subdomainTakeoverVuln = await _context.Vulnerabilities
                .FirstOrDefaultAsync(v => v.VulnerabilityName == VulnerabilityTypes.SubdomainTakeover);

            foreach (var item in results)
            {
                var scanResult = new ScanResult
                {
                    RequestId = scanRequest.RequestId,
                    Severity = item.Severity,
                    Summary = item.Summary,
                    Details = item.Summary,
                    VulnerabilityType = VulnerabilityTypes.SubdomainTakeover
                };
                _context.ScanResults.Add(scanResult);

            }

            scanRequest.Status = "Completed";
            scanRequest.CompletedAt = DateTime.UtcNow;

            _context.ScanRequests.Update(scanRequest);
            await _context.SaveChangesAsync();

            return Ok(results);
        }


        [HttpGet("scan-subdomain-list")]
        public async Task<IActionResult> GetLatestScanResults()
        {
            var latestScan = await _context.ScanRequests
                .OrderByDescending(r => r.StartedAt)
                .FirstOrDefaultAsync();

            if (latestScan == null)
                return NotFound("No scan history available.");

            var results = await _context.ScanResults
                .Where(r => r.RequestId == latestScan.RequestId)
                .ToListAsync();

            var combined = results.Select((result, index) => new DomainScanDto
            {
                ResultId = result.ResultId,
                Subdomain = _lastScanResults.ElementAtOrDefault(index)?.Subdomain,
                Severity = result.Severity,
                Summary = result.Summary,
                Details = result.Details,
                VulnerabilityType = result.VulnerabilityType
            }).ToList();

            return Ok(combined);
        }

        [HttpPost("report/domain")]
        public async Task<IActionResult> GenerateDomainReport([FromBody] string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return BadRequest("Domain is required.");

            var subdomains = await _extractor.GetSubdomainsAsync(domain);
            if (subdomains.Count == 0)
                return NotFound("No subdomains found.");

            var rawResults = await _scanner.CheckSubdomainsAsync(subdomains);

            List<DomainScanDto> results = rawResults.Select(r => new DomainScanDto
            {
                Subdomain = r.Subdomain,
                Severity = r.Severity,
                Summary = r.Summary,
                Details = r.Summary ?? "N/A", // fallback if no dedicated Details field
                VulnerabilityType = "Subdomain Takeover"
            }).ToList();

            using var memoryStream = new MemoryStream();
            Document document = new Document(PageSize.A4, 40, 40, 60, 40);
            PdfWriter.GetInstance(document, memoryStream);
            document.Open();

            Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
            Font bodyFont = FontFactory.GetFont(FontFactory.HELVETICA, 10);
            Font boldFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10);

            document.Add(new Paragraph($"Subdomain Takeover Report for {domain}", titleFont));
            document.Add(new Paragraph($"Generated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC\n\n", bodyFont));

            foreach (var result in results)
            {
                Paragraph p = new Paragraph();

                p.Add(new Chunk("Subdomain: ", boldFont));
                p.Add(new Phrase($"{result.Subdomain}\n", bodyFont));

                p.Add(new Chunk("Severity: ", boldFont));
                p.Add(new Phrase($"{result.Severity ?? "None"}\n", bodyFont));

                p.Add(new Chunk("Summary: ", boldFont));
                p.Add(new Phrase($"{result.Summary ?? "N/A"}\n", bodyFont));

                p.Add(new Chunk("Details: ", boldFont));
                p.Add(new Phrase($"{result.Details ?? "N/A"}\n", bodyFont));

                p.Add(new Chunk("Vulnerability: ", boldFont));
                p.Add(new Phrase($"{result.VulnerabilityType ?? "N/A"}\n", bodyFont));

                p.SpacingAfter = 12;
                document.Add(p);
            }

            document.Close();
            return File(memoryStream.ToArray(), "application/pdf", $"subdomain-report-{domain}.pdf");
        }
    }
}


// using System;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.EntityFrameworkCore;
// using System.Security.Claims;
// using Api.Models;
// using Microsoft.Extensions.Logging;
// using Api.Services;
// using Microsoft.Extensions.Configuration;
// using System.Net.Http;
// using Api.Services.Scanners;
// using Api.DTOs;

// namespace Api.Controllers
// {
//     /// <summary>
//     /// Controller for handling subdomain takeover scanning operations
//     /// </summary>
//     [Authorize(Roles = "User")]
//     [Route("api/")]
//     [ApiController]
//     public class SubdomainTakeoverController : ControllerBase
//     {
//         private readonly SubdomainTakeoverScanner _scanner;
//         private readonly ApiContext _context;
//         private readonly ILogger<SubdomainTakeoverController> _logger;

//         public SubdomainTakeoverController(
//             SubdomainTakeoverScanner scanner,
//             ApiContext context,
//             ILogger<SubdomainTakeoverController> logger)
//         {
//             _scanner = scanner;
//             _context = context;
//             _logger = logger;
//         }

//         [HttpPost("scan-subdomain")]
//         public async Task<IActionResult> ScanSubdomain([FromBody] SubdomainScanRequest request)
//         {
//             var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

//             try
//             {
//                 if (!IsValidSubdomain(request.Subdomain))
//                 {
//                     return BadRequest("Invalid subdomain.");
//                 }

//                 var normalizedSubdomain = NormalizeUrl(request.Subdomain);

//                 // Try to find or create the website entry
//                 var website = await _context.Websites
//                     .FirstOrDefaultAsync(w => w.Url == normalizedSubdomain);

//                 if (website == null)
//                 {
//                     website = new Website
//                     {
//                         Url = normalizedSubdomain,
//                         UserId = userId,
//                         CreatedAt = DateTime.UtcNow
//                     };
//                     _context.Websites.Add(website);
//                     await _context.SaveChangesAsync();
//                 }

//                 // Create scan request
//                 var scanRequest = new ScanRequest
//                 {
//                     UserId = userId,
//                     WebsiteId = website.WebsiteId,
//                     Status = "In Progress",
//                     StartedAt = DateTime.UtcNow
//                 };

//                 _context.ScanRequests.Add(scanRequest);
//                 await _context.SaveChangesAsync();

//                 // RUN SCANNER
//                 var result = await _scanner.ScanAsync(normalizedSubdomain);

//                 // Determine vulnerability from Severity string
//                 bool isVulnerable = !string.IsNullOrEmpty(result.Severity) &&
//                                    !result.Severity.Equals("None", StringComparison.OrdinalIgnoreCase);

//                 // Fetch vulnerability type record
//                 var vulnerability = await _context.Vulnerabilities
//                     .FirstOrDefaultAsync(v => v.VulnerabilityName == VulnerabilityTypes.SubdomainTakeover);

//                 // Save scan result
//                 var scanResult = new ScanResult
//                 {
//                     RequestId = scanRequest.RequestId,
//                     Severity = isVulnerable ? "High" : "None",
//                     Summary = result.Summary,
//                     Details = result.Details,
//                     VulnerabilityId = isVulnerable && vulnerability != null ? vulnerability.VulnerabilityId : null
//                 };

//                 scanRequest.Status = "Completed";
//                 scanRequest.CompletedAt = DateTime.UtcNow;

//                 _context.ScanResults.Add(scanResult);
//                 _context.ScanRequests.Update(scanRequest);
//                 await _context.SaveChangesAsync();

//                 return Ok(new
//                 {
//                     ScanId = scanRequest.RequestId,
//                     Subdomain = request.Subdomain,
//                     Status = scanRequest.Status,
//                     Vulnerable = isVulnerable,
//                     Summary = result.Summary
//                 });
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Error scanning subdomain: {Subdomain}", request.Subdomain);
//                 return StatusCode(500, new
//                 {
//                     Message = "Scan failed",
//                     Subdomain = request.Subdomain,
//                     Error = ex.Message,
//                     StackTrace = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development"
//                         ? ex.StackTrace
//                         : null
//                 });
//             }
//         }

//         [HttpGet("ScanSubdomain-result/{scanId}")]
//         public async Task<IActionResult> GetScanResult(int scanId)
//         {
//             var result = await _context.ScanResults
//                 .Include(r => r.ScanRequest)
//                 .ThenInclude(r => r.Website)
//                 .FirstOrDefaultAsync(r => r.RequestId == scanId);

//             if (result == null)
//                 return NotFound("Scan result not found.");

//             return Ok(new
//             {
//                 ScanId = scanId,
//                 Vulnerable = result.Severity != "None",
//                 Severity = result.Severity,
//                 Summary = result.Summary,
//                 Details = result.Details,
//                 Subdomain = result.ScanRequest?.Website?.Url
//             });
//         }

//         private bool IsValidSubdomain(string subdomain)
//         {
//             return !string.IsNullOrWhiteSpace(subdomain) &&
//                    subdomain.Length <= 253 &&
//                    !subdomain.Contains(" ");
//         }

//         private string NormalizeUrl(string subdomain)
//         {
//             if (subdomain.StartsWith("http://") || subdomain.StartsWith("https://"))
//             {
//                 return subdomain;
//             }
//             return $"http://{subdomain}";
//         }
//     }
// }
