using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using Microsoft.Extensions.Logging;
using Api.Services;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using Api.Services.Scanners;
using Api.DTOs;

namespace Api.Controllers
{
    /// <summary>
    /// Controller for handling subdomain takeover scanning operations
    /// </summary>
    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class SubdomainTakeoverController : ControllerBase
    {
        private readonly SubdomainTakeoverScanner _scanner;
        private readonly ApiContext _context;
        private readonly ILogger<SubdomainTakeoverController> _logger;

        public SubdomainTakeoverController(
            SubdomainTakeoverScanner scanner,
            ApiContext context,
            ILogger<SubdomainTakeoverController> logger)
        {
            _scanner = scanner;
            _context = context;
            _logger = logger;
        }

        [HttpPost("scan-subdomain")]
        public async Task<IActionResult> ScanSubdomain([FromBody] SubdomainScanRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            try
            {
                if (!IsValidSubdomain(request.Subdomain))
                {
                    return BadRequest("Invalid subdomain.");
                }

                var normalizedSubdomain = NormalizeUrl(request.Subdomain);

                // Try to find or create the website entry
                var website = await _context.Websites
                    .FirstOrDefaultAsync(w => w.Url == normalizedSubdomain);

                if (website == null)
                {
                    website = new Website
                    {
                        Url = normalizedSubdomain,
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.Websites.Add(website);
                    await _context.SaveChangesAsync();
                }

                // Create scan request
                var scanRequest = new ScanRequest
                {
                    UserId = userId,
                    WebsiteId = website.WebsiteId,
                    Status = "In Progress",
                    StartedAt = DateTime.UtcNow
                };

                _context.ScanRequests.Add(scanRequest);
                await _context.SaveChangesAsync();

                // RUN SCANNER
                var result = await _scanner.ScanAsync(normalizedSubdomain);

                // Determine vulnerability from Severity string
                bool isVulnerable = !string.IsNullOrEmpty(result.Severity) &&
                                   !result.Severity.Equals("None", StringComparison.OrdinalIgnoreCase);

                // Fetch vulnerability type record
                var vulnerability = await _context.Vulnerabilities
                    .FirstOrDefaultAsync(v => v.VulnerabilityName == VulnerabilityTypes.SubdomainTakeover);

                // Save scan result
                var scanResult = new ScanResult
                {
                    RequestId = scanRequest.RequestId,
                    Severity = isVulnerable ? "High" : "None",
                    Summary = result.Summary,
                    Details = result.Details,
                    VulnerabilityId = isVulnerable && vulnerability != null ? vulnerability.VulnerabilityId : null
                };

                scanRequest.Status = "Completed";
                scanRequest.CompletedAt = DateTime.UtcNow;

                _context.ScanResults.Add(scanResult);
                _context.ScanRequests.Update(scanRequest);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    ScanId = scanRequest.RequestId,
                    Subdomain = request.Subdomain,
                    Status = scanRequest.Status,
                    Vulnerable = isVulnerable,
                    Summary = result.Summary
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning subdomain: {Subdomain}", request.Subdomain);
                return StatusCode(500, new
                {
                    Message = "Scan failed",
                    Subdomain = request.Subdomain,
                    Error = ex.Message,
                    StackTrace = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development"
                        ? ex.StackTrace
                        : null
                });
            }
        }

        [HttpGet("ScanSubdomain-result/{scanId}")]
        public async Task<IActionResult> GetScanResult(int scanId)
        {
            var result = await _context.ScanResults
                .Include(r => r.ScanRequest)
                .ThenInclude(r => r.Website)
                .FirstOrDefaultAsync(r => r.RequestId == scanId);

            if (result == null)
                return NotFound("Scan result not found.");

            return Ok(new
            {
                ScanId = scanId,
                Vulnerable = result.Severity != "None",
                Severity = result.Severity,
                Summary = result.Summary,
                Details = result.Details,
                Subdomain = result.ScanRequest?.Website?.Url
            });
        }

        private bool IsValidSubdomain(string subdomain)
        {
            return !string.IsNullOrWhiteSpace(subdomain) &&
                   subdomain.Length <= 253 &&
                   !subdomain.Contains(" ");
        }

        private string NormalizeUrl(string subdomain)
        {
            if (subdomain.StartsWith("http://") || subdomain.StartsWith("https://"))
            {
                return subdomain;
            }
            return $"http://{subdomain}";
        }
    }
}
