using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using Newtonsoft.Json;
using Api.DTOs;
using Api.Services;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using iTextSharp.text;
using iTextSharp.text.pdf;
using System.IO;
using Newtonsoft.Json.Linq;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/xss")]
    [ApiController]
    public class XssController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly XssZapService _xssZapService;
        private readonly ILogger<XssController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;

        public XssController(IAuthService authService, ApiContext context, XssZapService xssZapService, ILogger<XssController> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _authService = authService;
            _context = context;
            _xssZapService = xssZapService;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        [HttpPost("scan-requests")]
        public async Task<IActionResult> XssScanner([FromBody] Website model, CancellationToken cancellationToken)
        {
            if (model == null || !ModelState.IsValid)
                return BadRequest("Invalid request. Please provide a valid website URL.");

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User ID not found.");

            model.UserId = userId;
            model.CreatedAt = DateTime.UtcNow;

            _context.Websites.Add(model);
            await _context.SaveChangesAsync(cancellationToken);

            var scanRequest = new ScanRequest
            {
                UserId = userId,
                WebsiteId = model.WebsiteId,
                Status = "In Progress",
                StartedAt = DateTime.UtcNow
            };

            _context.ScanRequests.Add(scanRequest);
            await _context.SaveChangesAsync(cancellationToken);

            try
            {
                var spiderId = await _xssZapService.StartSpiderAsync(model.Url, cancellationToken);
                string spiderStatus;
                do
                {
                    await Task.Delay(5000, cancellationToken);
                    spiderStatus = await _xssZapService.GetSpiderStatusAsync(spiderId, cancellationToken);
                } while (spiderStatus != "100");

                var scanId = await _xssZapService.StartScanAsync(model.Url, cancellationToken);
                scanRequest.ZAPScanId = scanId;
                await _context.SaveChangesAsync(cancellationToken);

                string scanStatus;
                const int maxRetries = 360; // 30 minutes
                int retries = 0;
                do
                {
                    await Task.Delay(5000, cancellationToken);
                    scanStatus = await _xssZapService.GetScanStatusAsync(scanId, cancellationToken);
                    retries++;
                } while (!scanStatus.Equals("100", StringComparison.OrdinalIgnoreCase) && retries < maxRetries);

                if (retries >= maxRetries)
                {
                    _logger.LogError($"Scan for {scanId} timed out.");
                    return StatusCode(504, "Scan timed out.");
                }

                scanRequest.Status = "Completed";
                scanRequest.CompletedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync(cancellationToken);
                _logger.LogInformation($"Returning redirectUrl: /xss/scan-results/{scanId}");

                return Ok(new
                {
                    Message = "Scan completed successfully!",
                    redirectUrl = $"/xss/scan-results/{scanId}"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during scan: {ex.Message}");
                return StatusCode(500, "An error occurred during the scan process.");
            }
        }

        [HttpGet("scan-results/{scanId}")]
        public async Task<IActionResult> GetXssScanResults([FromRoute] int scanId, CancellationToken cancellationToken)
        {
            try
            {
                var scanRequest = await _context.ScanRequests
                    .Include(r => r.Website)
                    .FirstOrDefaultAsync(r => r.ZAPScanId == scanId, cancellationToken);

                if (scanRequest == null)
                    return NotFound("Scan not found.");

                var alerts = await _xssZapService.GetProcessedScanResultsAsync(scanId, cancellationToken);

                if (!alerts.Any())
                {
                    _logger.LogWarning($"No XSS vulnerabilities found for scan ID {scanId} on {scanRequest.Website.Url}");
                    return Ok(new { Message = "No XSS vulnerabilities found.", Results = Array.Empty<ScanResult>() });
                }

                var reflectedXssVuln = await _context.Vulnerabilities
                    .FirstOrDefaultAsync(v => v.VulnerabilityName == VulnerabilityTypes.ReflectedXSS, cancellationToken);
                var storedXssVuln = await _context.Vulnerabilities
                    .FirstOrDefaultAsync(v => v.VulnerabilityName == VulnerabilityTypes.StoredXSS, cancellationToken);

                if (reflectedXssVuln == null || storedXssVuln == null)
                {
                    _logger.LogError("Required vulnerability types not found in database.");
                    return StatusCode(500, "Required vulnerability types not configured.");
                }

                var uniqueAlerts = alerts
                    .GroupBy(a => new { a.AffectedUrl, a.Payload, a.XssType })
                    .Select(g => g.First())
                    .ToList();

                var resultsToSave = new List<ScanResult>();
                foreach (var alert in uniqueAlerts)
                {
                    _logger.LogInformation($"Processing alert: {alert.XssType}, URL: {alert.AffectedUrl}");
                    var shortDescription = alert.Description.Length > 200
                        ? alert.Description.Substring(0, 200) + "..."
                        : alert.Description;

                    ScanResult result = null;
                    if (alert.XssType == VulnerabilityTypes.ReflectedXSS)
                    {
                        result = new ScanResult
                        {
                            RequestId = scanRequest.RequestId,
                            ZAPScanId = scanId,
                            Severity = alert.Risk,
                            Details = JsonConvert.SerializeObject(new
                            {
                                alert.XssType,
                                alert.AffectedUrl,
                                alert.Risk,
                                alert.Confidence,
                                Description = shortDescription,
                                alert.Solution,
                                alert.Payload
                            }),
                            VulnerabilityId = reflectedXssVuln.VulnerabilityId,
                            VulnerabilityType = VulnerabilityTypes.ReflectedXSS,
                            PayloadUsed = alert.Payload
                        };
                    }
                    else if (alert.XssType == VulnerabilityTypes.StoredXSS)
                    {
                        result = new ScanResult
                        {
                            RequestId = scanRequest.RequestId,
                            ZAPScanId = scanId,
                            Severity = alert.Risk,
                            Details = JsonConvert.SerializeObject(new
                            {
                                alert.XssType,
                                alert.AffectedUrl,
                                alert.Risk,
                                alert.Confidence,
                                Description = shortDescription,
                                alert.Solution,
                                alert.Payload
                            }),
                            VulnerabilityId = storedXssVuln.VulnerabilityId,
                            VulnerabilityType = VulnerabilityTypes.StoredXSS,
                            PayloadUsed = alert.Payload
                        };
                    }

                    if (result != null)
                    {
                        resultsToSave.Add(result);
                    }
                }

                var existingResults = await _context.ScanResults
                    .Where(r => r.RequestId == scanRequest.RequestId)
                    .ToListAsync(cancellationToken);

                if (!existingResults.Any())
                {
                    _logger.LogInformation($"Saving {resultsToSave.Count} scan results for RequestId {scanRequest.RequestId}");
                    await _context.ScanResults.AddRangeAsync(resultsToSave, cancellationToken);
                    await _context.SaveChangesAsync(cancellationToken);
                }

                return Ok(new { Message = "XSS scan results retrieved successfully.", Results = resultsToSave });
            }
            catch (KeyNotFoundException)
            {
                _logger.LogWarning($"Scan ID {scanId} not found in mapping.");
                return NotFound("Scan not found. Ensure the scan was started.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error retrieving scan results: {ex.Message}");
                return StatusCode(500, "Failed to retrieve scan results.");
            }
        }
[HttpGet("scan-results/{scanId}/pdf")]
public async Task<IActionResult> DownloadXssScanResultsPdf([FromRoute] int scanId, CancellationToken cancellationToken)
{
    try
    {
        var scanRequest = await _context.ScanRequests
            .Include(r => r.Website)
            .FirstOrDefaultAsync(r => r.ZAPScanId == scanId, cancellationToken);

        if (scanRequest == null)
            return NotFound("Scan not found.");

        var alerts = await _xssZapService.GetProcessedScanResultsAsync(scanId, cancellationToken);
        var uniqueAlerts = alerts
            .GroupBy(a => new { a.AffectedUrl, a.Payload, a.XssType })
            .Select(g => g.First())
            .ToList();

        using (var memoryStream = new MemoryStream())
        {
            var document = new Document(PageSize.A4, 40, 40, 60, 40);
            PdfWriter.GetInstance(document, memoryStream);
            document.Open();

            // Define fonts and colors
            var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16, new BaseColor(33, 37, 41));
            var sectionFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 12, new BaseColor(52, 58, 64));
            var bodyFont = FontFactory.GetFont(FontFactory.HELVETICA, 10, new BaseColor(73, 80, 87));
            var accentColor = new BaseColor(108, 117, 125);
            var lowSeverity = new BaseColor(111, 207, 151);
            var mediumSeverity = new BaseColor(255, 193, 7);
            var highSeverity = new BaseColor(220, 53, 69);
            var cardBackground = new BaseColor(248, 249, 250);

            // Title
            var title = new Paragraph("Cross-Site Scripting (XSS) Scan Report", titleFont);
            title.Alignment = Element.ALIGN_CENTER;
            title.SpacingAfter = 20;
            document.Add(title);

            // Scan Summary with styled table
            var summaryTable = new PdfPTable(1);
            summaryTable.WidthPercentage = 100;
            var summaryCell = new PdfPCell();
            summaryCell.BorderColor = accentColor;
            summaryCell.BorderWidth = 1;
            summaryCell.BackgroundColor = cardBackground;
            summaryCell.Padding = 10;

            var summary = new Paragraph();
            summary.Add(new Chunk("Scan Summary\n", sectionFont));
            // Derive website from the first alert's AffectedUrl to match results page
            var websiteUrl = "Unknown";
            if (uniqueAlerts.Any() && !string.IsNullOrEmpty(uniqueAlerts.First().AffectedUrl))
            {
                try
                {
                    var uri = new Uri(uniqueAlerts.First().AffectedUrl);
                    websiteUrl = $"{uri.Scheme}://{uri.Host}";
                }
                catch (UriFormatException)
                {
                    websiteUrl = uniqueAlerts.First().AffectedUrl; // Fallback to raw URL
                }
            }
            summary.Add(new Phrase($"Website: {websiteUrl}\n", bodyFont));
            summary.Add(new Phrase($"Scan Date: {DateTime.UtcNow:MM/dd/yyyy, hh:mm tt}\n", bodyFont));
            summary.Add(new Phrase($"Total Vulnerabilities Found: {uniqueAlerts.Count}\n", bodyFont));
            summaryCell.AddElement(summary);
            summaryTable.AddCell(summaryCell);
            document.Add(summaryTable);
            document.Add(new Paragraph(" ", bodyFont));

            // Vulnerability Findings
            var findingsTitle = new Paragraph("Vulnerability Findings", sectionFont);
            findingsTitle.SpacingBefore = 10;
            findingsTitle.SpacingAfter = 10;
            document.Add(findingsTitle);

            var groupedByType = uniqueAlerts.GroupBy(a => a.XssType);
            foreach (var group in groupedByType)
            {
                var typeHeader = new Paragraph($"{group.Key} Findings", sectionFont);
                typeHeader.SpacingBefore = 10;
                typeHeader.SpacingAfter = 5;
                document.Add(typeHeader);

                // Collect unique descriptions for this type
                var uniqueDescriptions = group.Select(a => a.Description)
                    .Distinct()
                    .Where(d => !string.IsNullOrEmpty(d))
                    .ToList();
                var descriptionLines = uniqueDescriptions.FirstOrDefault()?.Split('\n')
                    .Select(line => line.Trim())
                    .Where(line => !string.IsNullOrEmpty(line))
                    .ToList() ?? new List<string>();

                foreach (var alert in group)
                {
                    // Severity bar
                    var severityColor = alert.Risk.ToLower() == "high" ? highSeverity :
                                      alert.Risk.ToLower() == "medium" ? mediumSeverity : lowSeverity;
                    var severityBar = new PdfPTable(1);
                    severityBar.WidthPercentage = 100;
                    var severityCell = new PdfPCell(new Phrase(" ", bodyFont));
                    severityCell.BackgroundColor = severityColor;
                    severityCell.FixedHeight = 4;
                    severityCell.Border = 0;
                    severityBar.AddCell(severityCell);

                    // Vulnerability card
                    var cardTable = new PdfPTable(1);
                    cardTable.WidthPercentage = 100;
                    var cardCell = new PdfPCell();
                    cardCell.BorderColor = accentColor;
                    cardCell.BorderWidth = 1;
                    cardCell.BackgroundColor = cardBackground;
                    cardCell.Padding = 12;
                    cardCell.AddElement(severityBar);

                    var finding = new Paragraph();
                    finding.SpacingBefore = 8;
                    finding.Add(new Chunk($"Severity: ", sectionFont));
                    finding.Add(new Phrase($"{alert.Risk}\n", bodyFont));
                    // Payload formatted like the results page
                    finding.Add(new Chunk($"Payload: ", sectionFont));
                    finding.Add(new Phrase($"{alert.Payload}\n", bodyFont));

                    // Details as bullet points
                   // Details as bullet points
                    var detailsList = new List(false, 10f);
                    detailsList.SetListSymbol("• ");
                    detailsList.IndentationLeft = 10;
                    detailsList.Add(new ListItem(new Phrase($"Type: {alert.XssType}", sectionFont)));
                    detailsList.Add(new ListItem(new Phrase($"Affected URL: {alert.AffectedUrl}", sectionFont)));
                    detailsList.Add(new ListItem(new Phrase($"Risk: {alert.Risk}", sectionFont)));
                    detailsList.Add(new ListItem(new Phrase($"Confidence: {alert.Confidence}", sectionFont)));
                    detailsList.Add(new ListItem(new Phrase($"Payload: {alert.Payload}", sectionFont))); // Added Payload

                    cardCell.AddElement(detailsList);
                    cardTable.AddCell(cardCell);
                    document.Add(cardTable);
                    document.Add(new Paragraph(" ", bodyFont));
                }

                // Add Description once per type, formatted like remediation
                if (descriptionLines.Any())
                {
                    var descriptionPara = new Paragraph();
                    descriptionPara.Add(new Chunk($"Description for {group.Key}:\n", sectionFont));
                    var descList = new List(false, 10f);
                    descList.SetListSymbol("• ");
                    descList.IndentationLeft = 10;
                    foreach (var line in descriptionLines)
                    {
                        descList.Add(new ListItem(new Phrase(line, bodyFont)));
                    }
                    descriptionPara.Add(descList);
                    descriptionPara.SpacingBefore = 5;
                    descriptionPara.SpacingAfter = 10;
                    document.Add(descriptionPara);
                }

                // Common Remediation
                var remediation = alerts
                    .Where(a => a.XssType == group.Key)
                    .Select(a => a.Solution)
                    .Where(s => !string.IsNullOrEmpty(s))
                    .Distinct()
                    .SelectMany(s => s.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    .Select(s => s.Trim())
                    .ToArray();

                if (remediation.Any())
                {
                    var remediationPara = new Paragraph();
                    remediationPara.Add(new Chunk($"Common Remediation for {group.Key}:\n", sectionFont));
                    var remediationList = new List(false, 10f);
                    remediationList.SetListSymbol("• ");
                    remediationList.IndentationLeft = 10;
                    foreach (var line in remediation)
                    {
                        remediationList.Add(new ListItem(new Phrase(line, bodyFont)));
                    }
                    remediationPara.Add(remediationList);
                    remediationPara.SpacingBefore = 5;
                    remediationPara.SpacingAfter = 10;
                    document.Add(remediationPara);
                }
            }

            document.Close();

            var pdfBytes = memoryStream.ToArray();
            return File(pdfBytes, "application/pdf", $"XSS_Scan_Report_{scanId}.pdf");
        }
    }
    catch (Exception ex)
    {
        _logger.LogError($"Error generating PDF: {ex.Message}");
        return StatusCode(500, "Failed to generate PDF report.");
    }
}
       
    }
}