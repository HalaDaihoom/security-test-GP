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
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using iTextSharp.text;
using iTextSharp.text.pdf;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class SubdomainTakeOverController : ControllerBase
    {
        private readonly ApiContext _context;
        private readonly string _toolsPath = @"C:\Tools";
        private readonly ILogger<SubdomainTakeOverController> _logger;
        private readonly IHttpClientFactory _clientFactory;
        

        public SubdomainTakeOverController(ApiContext context, ILogger<SubdomainTakeOverController> logger, IHttpClientFactory clientFactory)
        {
            _context = context;
            _logger = logger;
            _clientFactory = clientFactory;
        }

        [HttpPost("takeovers")]
public async Task<IActionResult> CreateTakeoverScan([FromBody] DomainRequest request)
{
    if (string.IsNullOrWhiteSpace(request.Domain))
        return BadRequest(new { message = "Domain is required." });

    string domain = request.Domain.Trim();
    string subsFile = $"subs_{domain}.txt";

    try
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var website = await _context.Websites.FirstOrDefaultAsync(w => w.Url == domain);

        if (website == null)
        {
            website = new Website
            {
                Url = domain,
                CreatedAt = DateTime.UtcNow
            };
            _context.Websites.Add(website);
            await _context.SaveChangesAsync();
        }

        // 🟡 Get vulnerability entry with ID 8
        var subdomainTakeoverVuln = await _context.Vulnerabilities
            .FirstOrDefaultAsync(v => v.VulnerabilityId == 8);

        if (subdomainTakeoverVuln == null)
        {
            return StatusCode(500, new { message = "Subdomain Takeover vulnerability not found in database." });
        }

        // 🔹 Run assetfinder
        await RunCommandAndCaptureOutputAsync($"assetfinder.exe {domain} > {subsFile}");

        // 🔹 Run subzy
        var subzyOutput = await RunCommandAndCaptureOutputAsync($"subzy.exe run --targets {subsFile}");

        // 🔹 Clean ANSI escape codes
        string cleanedOutput = Regex.Replace(subzyOutput, @"\x1B\[[0-9;]*[a-zA-Z]", "");

        // 🔹 Save ScanRequest
        var scanRequest = new ScanRequest
        {
            UserId = userId,
            WebsiteId = website.WebsiteId,
            StartedAt = DateTime.UtcNow,
            CompletedAt = DateTime.UtcNow,
            Status = "Completed",
            VulnerabilityId = subdomainTakeoverVuln.VulnerabilityId // ✅ link to existing vulnerability
        };

        _context.ScanRequests.Add(scanRequest);
        await _context.SaveChangesAsync();

        // 🔹 Save ScanResults
        var lines = cleanedOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var result = new ScanResult
            {
                RequestId = scanRequest.RequestId,
                Severity = line.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase)
                    ? "Secured"
                    : line.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase)
                        ? "High"
                        : "Info",
                Details = line,
                VulnerabilityType = "Subdomain Takeover",
                VulnerabilityId = subdomainTakeoverVuln.VulnerabilityId // ✅ also set for results
            };

            _context.ScanResults.Add(result);
        }

        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Scan completed",
            domain = domain,
            results = lines
        });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Subzy scan failed");
        return StatusCode(500, new { message = "An error occurred during scanning", error = ex.Message });
    }
}


        // [HttpPost("takeovers")]
        // // public async Task<IActionResult> ScanWithSubzy([FromBody] DomainRequest request)
        // public async Task<IActionResult> CreateTakeoverScan([FromBody] DomainRequest request)
        // {
        //     if (string.IsNullOrWhiteSpace(request.Domain))
        //         return BadRequest(new { message = "Domain is required." });

        //     string domain = request.Domain.Trim();
        //     string subsFile = $"subs_{domain}.txt";

        //     try
        //     {
        //         var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        //         var website = await _context.Websites.FirstOrDefaultAsync(w => w.Url == domain);

        //         if (website == null)
        //         {
        //             website = new Website
        //             {
        //                 Url = domain,
        //                 CreatedAt = DateTime.UtcNow
        //             };
        //             _context.Websites.Add(website);
        //             await _context.SaveChangesAsync();
        //         }


        //         //  Extract subdomains
        //         await RunCommandAndCaptureOutputAsync($"assetfinder.exe {domain} > {subsFile}");

        //         // Run Subzy
        //         var subzyOutput = await RunCommandAndCaptureOutputAsync($"subzy.exe run --targets {subsFile}");

        //         // Clean output
        //         string cleanedOutput = Regex.Replace(subzyOutput, @"\x1B\[[0-9;]*[a-zA-Z]", "");

        //         //  Save ScanRequest
        //         var scanRequest = new ScanRequest
        //         {
        //             UserId = userId,
        //             WebsiteId = website.WebsiteId,
        //             StartedAt = DateTime.UtcNow,
        //             CompletedAt = DateTime.UtcNow,
        //             Status = "Completed"
        //         };

        //         _context.ScanRequests.Add(scanRequest);
        //         await _context.SaveChangesAsync();

        //         // Save results
        //         var lines = cleanedOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        //         foreach (var line in lines)
        //         {
        //             var result = new ScanResult
        //             {
        //                 RequestId = scanRequest.RequestId,
        //                 Severity = line.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase)
        //                 ? "Secured"
        //                 : line.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase)
        //                     ? "High"
        //                     : "Info",
        //                 Details = line,
        //                 VulnerabilityType = "Subdomain Takeover"
        //             };

        //             _context.ScanResults.Add(result);
        //         }

        //         await _context.SaveChangesAsync();

        //         return Ok(new
        //         {
        //             message = "Scan completed",
        //             domain = domain,
        //             results = lines
        //         });
        //     }
        //     catch (Exception ex)
        //     {
        //         _logger.LogError(ex, "Subzy scan failed");
        //         return StatusCode(500, new { message = "An error occurred during scanning", error = ex.Message });
        //     }
        // }
        [HttpGet("takeover-reports/{domain}")]
public async Task<IActionResult> GetTakeoverReport(string domain)
{
    if (string.IsNullOrWhiteSpace(domain))
        return BadRequest("Domain is required.");

    domain = domain.Trim();

    var website = await _context.Websites.FirstOrDefaultAsync(w => w.Url == domain);
    if (website == null)
        return NotFound(new { message = "Website not registered." });

    var latestScan = await _context.ScanRequests
        .Where(s => s.WebsiteId == website.WebsiteId)
        .OrderByDescending(s => s.StartedAt)
        .FirstOrDefaultAsync();

    if (latestScan == null)
        return NotFound(new { message = "No scan found for this domain." });

    var results = await _context.ScanResults
        .Where(r => r.RequestId == latestScan.RequestId)
        .ToListAsync();

    // Count result types
    int vulnerableCount = results.Count(r => r.Details != null &&
        r.Details.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase) &&
        !r.Details.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase));

    int safeCount = results.Count(r => r.Details != null &&
        r.Details.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase));

    int errorCount = results.Count(r => r.Details != null &&
        r.Details.Contains("HTTP ERROR", StringComparison.OrdinalIgnoreCase));

    using var memoryStream = new MemoryStream();
    Document document = new Document(PageSize.A4, 40, 40, 60, 40);
    PdfWriter.GetInstance(document, memoryStream);
    document.Open();

    Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 18);
    Font subtitleFont = FontFactory.GetFont(FontFactory.HELVETICA, 12);
    Font headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10);
    Font cellFont = FontFactory.GetFont(FontFactory.HELVETICA, 9);

    // Header
    document.Add(new Paragraph("BugSloth - Subdomain Takeover Scan Report", titleFont)
    {
        Alignment = Element.ALIGN_CENTER
    });
    document.Add(new Paragraph($"Target Domain: {domain}", subtitleFont));
    document.Add(new Paragraph($"Generated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC", subtitleFont));
    document.Add(Chunk.NEWLINE);

    // Scanner metadata block
    var metadataLines = results
        .Where(r => r.Details != null && r.Details.TrimStart().StartsWith("["))
        .Where(r => !r.Details.Contains("."))
        .Select(r => r.Details)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (metadataLines.Any())
    {
        document.Add(new Paragraph("Scanner Configuration:", headerFont));
        foreach (var line in metadataLines)
        {
            document.Add(new Paragraph(line, cellFont));
        }
        document.Add(Chunk.NEWLINE);
    }

    // Table
    PdfPTable table = new PdfPTable(3) { WidthPercentage = 100 };
    table.SetWidths(new float[] { 2, 2, 6 });

    PdfPCell tableHeader = new PdfPCell(new Phrase("Subdomain Scan Results", titleFont))
    {
        Colspan = 3,
        HorizontalAlignment = Element.ALIGN_CENTER,
        BackgroundColor = BaseColor.LIGHT_GRAY,
        Padding = 8
    };
    table.AddCell(tableHeader);

    table.AddCell(new Phrase("Severity", headerFont));
    table.AddCell(new Phrase("Status", headerFont));
    table.AddCell(new Phrase("Details", headerFont));

    var uniqueDetails = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var r in results)
    {
        string detail = r.Details ?? "";

        if (!detail.Contains(".")) continue; // Skip non-subdomain rows

        if (!uniqueDetails.Add(detail)) continue; // Skip duplicates

        string status;
        if (detail.Contains("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase))
            status = "✅ Not Vulnerable";
        else if (detail.Contains("VULNERABLE", StringComparison.OrdinalIgnoreCase))
            status = "⚠️ Vulnerable";
        else if (detail.Contains("HTTP ERROR", StringComparison.OrdinalIgnoreCase))
            status = "❌ HTTP Error";
        else
            status = "ℹ️ Unknown";

        PdfPCell severityCell = new PdfPCell(new Phrase(r.Severity ?? "None", cellFont));
        PdfPCell statusCell = new PdfPCell(new Phrase(status, cellFont));
        PdfPCell detailsCell = new PdfPCell(new Phrase(detail, cellFont));

        table.AddCell(severityCell);
        table.AddCell(statusCell);
        table.AddCell(detailsCell);
    }

    document.Add(table);

    // Summary
    document.Add(Chunk.NEWLINE);
    document.Add(new Paragraph("Summary", headerFont));
    document.Add(new Paragraph($"✅ Not Vulnerable: {safeCount}", cellFont));
    document.Add(new Paragraph($"⚠️ Vulnerable: {vulnerableCount}", cellFont));
    document.Add(new Paragraph($"❌ Errors: {errorCount}", cellFont));

    document.Close();

    var safeDomain = string.Join("_", domain.Split(System.IO.Path.GetInvalidFileNameChars()));
    return File(memoryStream.ToArray(), "application/pdf", $"subzy-report-{safeDomain}.pdf");
}

        private async Task<string> RunCommandAndCaptureOutputAsync(string command)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo("cmd.exe", $"/C {command}")
                {
                    WorkingDirectory = _toolsPath,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = await process.StandardOutput.ReadToEndAsync();
            output += await process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            return output;
        }
    }

    public class DomainRequest
    {
        public string Domain { get; set; }
    }


}

