
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Api.Models;
using Api.Services;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Api.Models.DTOs;
using Microsoft.EntityFrameworkCore;
using iTextSharp.text;
using iTextSharp.text.pdf;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class SqlInjController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly ILogger<SqlInjController> _logger;
        private readonly SqlInjectionScanner _scanner;

        public SqlInjController(IAuthService authService, ApiContext context,
            SqlInjectionScanner scanner,
            ILogger<SqlInjController> logger)
        {
            _authService = authService;
            _context = context;
            _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

       


        [HttpPost("scan")]
        public async Task<ActionResult<object>> Scan([FromBody] SRequest request, CancellationToken cancellationToken)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User ID not found.");

            if (string.IsNullOrEmpty(request.Url))
            {
                return BadRequest(new List<SResult>
        {
            new SResult
            {
                Url = request.Url,
                IsVulnerable = false,
                Details = "Invalid or empty URL provided",
                VulnerableParameters = new List<string>()
            }
        });
            }

            try
            {
                // Ensure website exists or create it
                var website = await _context.Websites
                    .FirstOrDefaultAsync(w => w.Url == request.Url && w.UserId == userId, cancellationToken);

                if (website == null)
                {
                    website = new Website
                    {
                        Url = request.Url,
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.Websites.Add(website);
                    await _context.SaveChangesAsync(cancellationToken);
                }

                // Create scan request entry
                var scanRequest = new ScanRequest
                {
                    UserId = userId,
                    WebsiteId = website.WebsiteId,
                    Status = "InProgress",
                    StartedAt = DateTime.UtcNow
                };

                _context.ScanRequests.Add(scanRequest);
                await _context.SaveChangesAsync(cancellationToken); // Get RequestId

                // Perform scan
                var results = await _scanner.TestSqlInjection(request.Url, request.DeepScan, cancellationToken);

                // Save scan results
                var scanResults = results.Select(r => new ScanResult
                {
                    RequestId = scanRequest.RequestId,
                    Severity = r.IsVulnerable ? "High" : "None",
                    Details = r.Details,
                    Summary = r.IsVulnerable
                        ? $"SQL injection vulnerability detected on {r.Url} with payload: {r.PayloadUsed}"
                        : "No SQL injection vulnerabilities found",
                    PayloadUsed = r.PayloadUsed,                      // ✅ store payload
                    VulnerabilityType = "Sql Injection",                     // ✅ mark as manual
                    VulnerabilityId = r.IsVulnerable ? 6 : null

                    // Url = r.Url
                }).ToList();

                _context.ScanResults.AddRange(scanResults); // ✅ Ensure EF tracks these
                scanRequest.Status = "Completed";
                scanRequest.CompletedAt = DateTime.UtcNow;
                scanRequest.VulnerabilityId = 6;
                await _context.SaveChangesAsync(cancellationToken); // Save everything

                // Return scan results and redirect
                return Ok(new
                {
                    Message = "Scan completed successfully!",
                    redirectUrl = $"/scanner/sql-scan-results/{scanRequest.RequestId}",
                    Results = results
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error scanning URL {request.Url} with deepScan={request.DeepScan}");
                return StatusCode(500, new List<SResult>
        {
            new SResult
            {
                Url = request.Url,
                IsVulnerable = false,
                Details = $"Scan failed: {ex.Message}",
                VulnerableParameters = new List<string>()
            }
        });
            }
        }














        [HttpGet("sql-result/{scanId}")]
        public async Task<IActionResult> GetSqlResult([FromRoute] int scanId, CancellationToken cancellationToken)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            _logger.LogInformation($"GetSqlResult called with scanId={scanId}, userId={userId}");

            if (string.IsNullOrEmpty(userId))
                return Unauthorized(new { Message = "User ID not found." });

            try
            {
                var scanRequest = await _context.ScanRequests
                    .Include(sr => sr.ScanResults)
                    .Include(sr => sr.Website)
                    .FirstOrDefaultAsync(sr => sr.RequestId == scanId && sr.UserId == userId, cancellationToken);

                if (scanRequest == null)
                {
                    _logger.LogWarning($"No ScanRequest found for scanId={scanId}, userId={userId}");
                    return NotFound($"Scan with ID {scanId} not found or you do not have permission to access it.");
                }

                var results = scanRequest.ScanResults?.Select(sr => new SqlScanResultDto
                {
                    VulnerabilityType = sr.VulnerabilityType,
                    Severity = sr.Severity,
                    Details = sr.Details,
                    Summary = sr.Summary,
                    Url = scanRequest.Website?.Url ?? "",
                    PayloadUsed = sr.PayloadUsed,
                    
                }).ToList() ?? new List<SqlScanResultDto>();

                if (!results.Any())
                {
                    results.Add(new SqlScanResultDto
                    {
                        VulnerabilityType = null,
                        Severity = "None",
                        Details = "No scan results available",
                        Summary = "No scan results available",
                        Url = scanRequest.Website?.Url ?? "",
                     PayloadUsed = null,

                    });
                }

                return Ok(results);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving scan result for scanId {scanId}");
                return StatusCode(500, new List<SqlScanResultDto>
        {
            new SqlScanResultDto
            {
                VulnerabilityType = null,
                Severity = "None",
                Details = $"Failed to retrieve scan result: {ex.Message}",
                Summary = $"Failed to retrieve scan result: {ex.Message}",
                Url = ""
            }
        });
            }
        }









        // [HttpGet("report/{requestId}")]
        // public async Task<IActionResult> GenerateXSSReport(int requestId, CancellationToken cancellationToken)
        // {
        //     var results = await _context.ScanResults
        //         .Where(r => r.RequestId == requestId)
        //         .Include(r => r.Vulnerability)
        //         .Include(r => r.ScanRequest)
        //         .ThenInclude(sr => sr.Website)
        //         .ToListAsync(cancellationToken);

        //     if (!results.Any())
        //         return NotFound("No results found");

        //     using (var memoryStream = new MemoryStream())
        //     {
        //         Document document = new Document(PageSize.A4, 40, 40, 60, 40);
        //         PdfWriter writer = PdfWriter.GetInstance(document, memoryStream);
        //         document.Open();

        //         Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16, new BaseColor(33, 37, 41));
        //         Font sectionFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 12, new BaseColor(52, 58, 64));
        //         Font bodyFont = FontFactory.GetFont(FontFactory.HELVETICA, 10, new BaseColor(73, 80, 87));
        //         BaseColor accentColor = new BaseColor(108, 117, 125);
        //         BaseColor lowSeverity = new BaseColor(111, 207, 151);
        //         BaseColor mediumSeverity = new BaseColor(255, 193, 7);
        //         BaseColor highSeverity = new BaseColor(220, 53, 69);
        //         BaseColor cardBackground = new BaseColor(248, 249, 250);

        //         Paragraph title = new Paragraph("SQL Injection Scan Report", titleFont)
        //         {
        //             Alignment = Element.ALIGN_CENTER,
        //             SpacingAfter = 20
        //         };
        //         document.Add(title);

        //         PdfPTable summaryTable = new PdfPTable(1) { WidthPercentage = 100 };
        //         PdfPCell summaryCell = new PdfPCell
        //         {
        //             BorderColor = accentColor,
        //             BorderWidth = 1,
        //             BackgroundColor = cardBackground,
        //             Padding = 10
        //         };

        //         Paragraph summary = new Paragraph();
        //         summary.Add(new Chunk("Scan Summary\n", sectionFont));
        //         summary.Add(new Phrase($"Website: {results.First().ScanRequest.Website.Url}\n", bodyFont));
        //         summary.Add(new Phrase($"Scan Date: {results.First().ScanRequest.StartedAt:yyyy-MM-dd HH:mm}\n", bodyFont));
        //         summary.Add(new Phrase($"Total Vulnerabilities Found: {results.Count}\n", bodyFont));

        //         summaryCell.AddElement(summary);
        //         summaryTable.AddCell(summaryCell);
        //         document.Add(summaryTable);

        //         document.Add(new Paragraph(" ", bodyFont));
        //         Paragraph findingsTitle = new Paragraph("Vulnerability Findings", sectionFont)
        //         {
        //             SpacingBefore = 10,
        //             SpacingAfter = 10
        //         };
        //         document.Add(findingsTitle);

        //         foreach (var result in results)
        //         {
        //             PdfPTable cardTable = new PdfPTable(1) { WidthPercentage = 100 };
        //             PdfPCell cardCell = new PdfPCell
        //             {
        //                 BorderColor = accentColor,
        //                 BorderWidth = 1,
        //                 BackgroundColor = cardBackground,
        //                 Padding = 12
        //             };

        //             BaseColor severityColor = result.Severity == "High" ? highSeverity :
        //                                       result.Severity == "Medium" ? mediumSeverity : lowSeverity;

        //             PdfPTable severityBar = new PdfPTable(1) { WidthPercentage = 100 };
        //             PdfPCell severityCell = new PdfPCell(new Phrase(" ", bodyFont))
        //             {
        //                 BackgroundColor = severityColor,
        //                 FixedHeight = 4,
        //                 Border = 0
        //             };
        //             severityBar.AddCell(severityCell);
        //             cardCell.AddElement(severityBar);

        //             Paragraph finding = new Paragraph { SpacingBefore = 8 };
        //             finding.Add(new Chunk($"Vulnerability Type: ", sectionFont));
        //             finding.Add(new Phrase($"{result.VulnerabilityType ?? "Unknown"}\n", bodyFont));
        //             finding.Add(new Chunk($"Severity: ", sectionFont));
        //             finding.Add(new Phrase($"{result.Severity ?? "Unknown"}\n", bodyFont));
        //             finding.Add(new Chunk($"Payload: ", sectionFont));
        //             finding.Add(new Phrase($"{result.PayloadUsed ?? "None"}\n", bodyFont));
        //             finding.Add(new Chunk($"Details: ", sectionFont));
        //             finding.Add(new Phrase($"{result.Details ?? "No details available"}\n", bodyFont));
        //             // finding.Add(new Chunk($"Remediation: ", sectionFont));
        //             // finding.Add(new Phrase($"{result.Vulnerability?.Remediation ?? "No remediation provided"}", bodyFont));

        //             cardCell.AddElement(finding);
        //             cardTable.AddCell(cardCell);
        //             document.Add(cardTable);
        //             document.Add(new Paragraph(" ", bodyFont));
        //         }

        //         document.Close();
        //         byte[] pdfBytes = memoryStream.ToArray();
        //         return File(pdfBytes, "application/pdf", $"Sql-report-{requestId}.pdf");
        //     }

        // }


        [HttpGet("report/{requestId}")]
        public async Task<IActionResult> GenerateXSSReport(int requestId, CancellationToken cancellationToken)
        {
            // Fetch related scan results from the database
            var results = await _context.ScanResults
                .Where(r => r.RequestId == requestId)
                .Include(r => r.Vulnerability)
                .Include(r => r.ScanRequest)
                    .ThenInclude(sr => sr.Website)
                .ToListAsync(cancellationToken);

            // If no results are found, return 404
            if (!results.Any())
                return NotFound("No results found for the specified request ID.");

            using var memoryStream = new MemoryStream();
            var document = new Document(PageSize.A4, 40, 40, 60, 40);
            var writer = PdfWriter.GetInstance(document, memoryStream);
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

            // Header
            var title = new Paragraph("SQL Injection Scan Report", titleFont)
            {
                Alignment = Element.ALIGN_CENTER,
                SpacingAfter = 20
            };
            document.Add(title);

            // Summary Section
            var summaryTable = new PdfPTable(1) { WidthPercentage = 100 };
            var summaryCell = new PdfPCell
            {
                BorderColor = accentColor,
                BorderWidth = 1,
                BackgroundColor = cardBackground,
                Padding = 10
            };

            var scan = results.First().ScanRequest;
            var summaryParagraph = new Paragraph
    {
        new Chunk("Scan Summary\n", sectionFont),
        new Phrase($"Website: {scan.Website.Url}\n", bodyFont),
        new Phrase($"Scan Date: {scan.StartedAt:yyyy-MM-dd HH:mm}\n", bodyFont),
        new Phrase($"Total Vulnerabilities Found: {results.Count}\n", bodyFont)
    };

            summaryCell.AddElement(summaryParagraph);
            summaryTable.AddCell(summaryCell);
            document.Add(summaryTable);

            document.Add(new Paragraph(" ", bodyFont)); // Spacer

            // Vulnerability Findings Section
            var findingsTitle = new Paragraph("Vulnerability Findings", sectionFont)
            {
                SpacingBefore = 10,
                SpacingAfter = 10
            };
            document.Add(findingsTitle);

            foreach (var result in results)
            {
                var cardTable = new PdfPTable(1) { WidthPercentage = 100 };
                var cardCell = new PdfPCell
                {
                    BorderColor = accentColor,
                    BorderWidth = 1,
                    BackgroundColor = cardBackground,
                    Padding = 12
                };

                // Severity Bar
                BaseColor severityColor = result.Severity switch
                {
                    "High" => highSeverity,
                    "Medium" => mediumSeverity,
                    "Low" => lowSeverity,
                    _ => accentColor
                };

                var severityBar = new PdfPTable(1) { WidthPercentage = 100 };
                var severityCell = new PdfPCell(new Phrase(" "))
                {
                    BackgroundColor = severityColor,
                    FixedHeight = 4,
                    Border = Rectangle.NO_BORDER
                };
                severityBar.AddCell(severityCell);
                cardCell.AddElement(severityBar);

                // Finding Details
                var findingParagraph = new Paragraph { SpacingBefore = 8 };
                findingParagraph.Add(new Chunk("Vulnerability Type: ", sectionFont));
                findingParagraph.Add(new Phrase($"{result.VulnerabilityType ?? "Unknown"}\n", bodyFont));

                findingParagraph.Add(new Chunk("Severity: ", sectionFont));
                findingParagraph.Add(new Phrase($"{result.Severity ?? "Unknown"}\n", bodyFont));

                findingParagraph.Add(new Chunk("Payload: ", sectionFont));
                findingParagraph.Add(new Phrase($"{result.PayloadUsed ?? "N/A"}\n", bodyFont));

                // findingParagraph.Add(new Chunk("Details: ", sectionFont));
                // findingParagraph.Add(new Phrase($"{result.Details ?? "No details available."}\n", bodyFont));
                findingParagraph.Add(new Chunk("Details: ", sectionFont));
                findingParagraph.Add(new Phrase($"{result.Summary ?? "No details available."}\n", bodyFont));

                // if (!string.IsNullOrEmpty(result.Vulnerability?.Remediation))
                // {
                //     findingParagraph.Add(new Chunk("Remediation: ", sectionFont));
                //     findingParagraph.Add(new Phrase($"{result.Vulnerability.Remediation}\n", bodyFont));
                // }

                cardCell.AddElement(findingParagraph);
                cardTable.AddCell(cardCell);
                document.Add(cardTable);
                document.Add(new Paragraph(" ", bodyFont)); // Spacer
            }

            document.Close();
            var pdfBytes = memoryStream.ToArray();
            var fileName = $"sql-report-{requestId}.pdf";
            return File(pdfBytes, "application/pdf", fileName);
        }




        



    }
}