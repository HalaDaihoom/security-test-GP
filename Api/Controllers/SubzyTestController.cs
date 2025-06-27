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
    public class SubzyController : ControllerBase
    {
        private readonly ApiContext _context;
        private readonly string _toolsPath = @"C:\Tools";
        private readonly ILogger<SubzyController> _logger;
        private readonly IHttpClientFactory _clientFactory;
        

        public SubzyController(ApiContext context, ILogger<SubzyController> logger, IHttpClientFactory clientFactory)
        {
            _context = context;
            _logger = logger;
            _clientFactory = clientFactory;
        }

        [HttpPost("Scan-with-subzy")]
        public async Task<IActionResult> ScanWithSubzy([FromBody] DomainRequest request)
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


                //  Extract subdomains
                await RunCommandAndCaptureOutputAsync($"assetfinder.exe {domain} > {subsFile}");

                // Run Subzy
                var subzyOutput = await RunCommandAndCaptureOutputAsync($"subzy.exe run --targets {subsFile}");

                // Clean output
                string cleanedOutput = Regex.Replace(subzyOutput, @"\x1B\[[0-9;]*[a-zA-Z]", "");

                //  Save ScanRequest
                var scanRequest = new ScanRequest
                {
                    UserId = userId,
                    WebsiteId = website.WebsiteId,
                    StartedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow,
                    Status = "Completed"
                };

                _context.ScanRequests.Add(scanRequest);
                await _context.SaveChangesAsync();

                // Save results
                var lines = cleanedOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var result = new ScanResult
                    {
                        RequestId = scanRequest.RequestId,
                        Severity = line.Contains("VULNERABLE") ? "High" : "Info",
                        Details = line,
                        VulnerabilityType = "Subdomain Takeover"
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

        [HttpPost("report/subzy")]
        public async Task<IActionResult> GenerateSubzyReport([FromBody] DomainRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Domain))
                return BadRequest("Domain is required.");

            string domain = request.Domain.Trim();

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

            using var memoryStream = new MemoryStream();
            Document document = new Document(PageSize.A4, 40, 40, 60, 40);
            PdfWriter.GetInstance(document, memoryStream);
            document.Open();

            Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
            Font headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10);
            Font cellFont = FontFactory.GetFont(FontFactory.HELVETICA, 9);

            document.Add(new Paragraph($"Subzy Scan Report for {domain}", titleFont));
            document.Add(new Paragraph($"Generated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC\n\n", cellFont));

            PdfPTable table = new PdfPTable(3) { WidthPercentage = 100 };
            table.SetWidths(new float[] { 2, 1, 6 });

            table.AddCell(new PdfPCell(new Phrase("Severity", headerFont)));
            table.AddCell(new PdfPCell(new Phrase("Vulnerability", headerFont)));
            table.AddCell(new PdfPCell(new Phrase("Details", headerFont)));

            foreach (var r in results)
            {
                table.AddCell(new PdfPCell(new Phrase(r.Severity ?? "None", cellFont)));
                table.AddCell(new PdfPCell(new Phrase(r.VulnerabilityType ?? "N/A", cellFont)));
                table.AddCell(new PdfPCell(new Phrase(r.Details ?? "N/A", cellFont)));
            }

            document.Add(table);
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
