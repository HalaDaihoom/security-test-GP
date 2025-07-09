using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Api.Services; // Your service
using Api.Models.DTOs;
using System.Security.Claims;
using Api.Models;
using iTextSharp.text;
using iTextSharp.text.pdf;
using Microsoft.AspNetCore.Authorization;

[Authorize(Roles = "User")]
[ApiController]
[Route("api/")]
public class SqlInjectionController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly SqlInjectionService _sqlInjectionService;
    private readonly ILogger<SqlInjectionController> _logger;
    private readonly ApiContext _context; // Your DbContext

    public SqlInjectionController(IAuthService authService,SqlInjectionService sqlInjectionService, ILogger<SqlInjectionController> logger, ApiContext context)
    {
        _sqlInjectionService = sqlInjectionService;
        _logger = logger;
        _context = context;
         _authService = authService;
    }

    // [HttpPost("sql-scan-requests")]
    // public async Task<IActionResult> StartSqlInjectionScanRequest([FromBody] Website model, CancellationToken cancellationToken)
    // {
    //     if (model == null || !ModelState.IsValid)
    //         return BadRequest("Invalid request. Please provide a valid website URL.");

    //     var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    //     if (string.IsNullOrEmpty(userId))
    //         return Unauthorized("User ID not found.");

    //     // Store website entry
    //     model.UserId = userId;
    //     model.CreatedAt = DateTime.UtcNow;
    //     _context.Websites.Add(model);
    //     await _context.SaveChangesAsync(cancellationToken);

    //     // Create ScanRequest entry
    //     var scanRequest = new ScanRequest
    //     {
    //         UserId = userId,
    //         WebsiteId = model.WebsiteId,
    //         Status = "In Progress",
    //         StartedAt = DateTime.UtcNow
    //     };

    //     _context.ScanRequests.Add(scanRequest);
    //     await _context.SaveChangesAsync(cancellationToken);

    //     try
    //     {
    //         // Start spider limited to 3 layers
    //         var spiderId = await _sqlInjectionService.StartSpiderAsync(model.Url, cancellationToken);
    //         await _sqlInjectionService.WaitForSpiderAsync(spiderId);

    //         // Start SQL Injection scan
    //         var scanId = await _sqlInjectionService.StartSqlInjectionScanAsync(model.Url);
    //         scanRequest.ZAPScanId = scanId;
    //         await _context.SaveChangesAsync(cancellationToken);

    //         // Wait for scan completion
    //         await _sqlInjectionService.WaitForScanCompletionAsync(scanId);

    //         scanRequest.Status = "Completed";
    //         scanRequest.CompletedAt = DateTime.UtcNow;
    //         scanRequest.VulnerabilityId = 6;
    //         await _context.SaveChangesAsync(cancellationToken);

    //         return Ok(new
    //         {
    //             Message = "SQL Injection scan completed successfully.",
    //             redirectUrl = $"/scanner/sql-injection-results/{scanRequest.RequestId}"
    //         });
    //     }
    //     catch (Exception ex)
    //     {
    //         _logger.LogError(ex, "Error during SQL Injection scan");
    //         scanRequest.Status = "Failed";
    //         await _context.SaveChangesAsync(cancellationToken);
    //         return StatusCode(500, "An error occurred during SQL Injection scan.");
    //     }
    // }







    [HttpPost("sql-scan-requests")]
    public async Task<IActionResult> StartSqlInjectionScanRequest([FromBody] Website model, CancellationToken cancellationToken)
    {
        if (model == null || !ModelState.IsValid || !IsValidUrl(model.Url))
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
            var spiderId = await _sqlInjectionService.StartSpiderAsync(model.Url, cancellationToken);
            await _sqlInjectionService.WaitForSpiderAsync(spiderId);

            var scanId = await _sqlInjectionService.StartSqlInjectionScanAsync(model.Url);
            scanRequest.ZAPScanId = scanId;
            await _context.SaveChangesAsync(cancellationToken);

            await _sqlInjectionService.WaitForScanCompletionAsync(scanId);

            scanRequest.Status = "Completed";
            scanRequest.CompletedAt = DateTime.UtcNow;
            scanRequest.VulnerabilityId = 6;
            await _context.SaveChangesAsync(cancellationToken);

            return Ok(new
            {
                Message = "SQL Injection scan completed successfully.",
                redirectUrl = $"/scanner/sql-injection-results/{scanRequest.RequestId}"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during SQL Injection scan");
            scanRequest.Status = "Failed";
            await _context.SaveChangesAsync(cancellationToken);
            return StatusCode(500, "An error occurred during SQL Injection scan.");
        }
    }

    private bool IsValidUrl(string url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out Uri? validatedUri)
               && (validatedUri.Scheme == Uri.UriSchemeHttp || validatedUri.Scheme == Uri.UriSchemeHttps)
               && !string.IsNullOrWhiteSpace(validatedUri.Host);
    }


    [HttpGet("sql-injection-results/{requestId}")]
    public async Task<IActionResult> GetSqlInjectionResults([FromRoute] int requestId, CancellationToken cancellationToken)
    {
        try
        {
            var scanRequest = await _context.ScanRequests
                .Include(r => r.Website)
                .FirstOrDefaultAsync(r => r.RequestId == requestId, cancellationToken);

            if (scanRequest == null)
                return NotFound("Scan not found.");

            string baseUrl = scanRequest.Website.Url;
            var results = await _sqlInjectionService.GetSqlInjectionResultsAsync(baseUrl);

            // Store results into ScanResults if not already stored
            var existingResults = await _context.ScanResults
                .Where(r => r.RequestId == requestId)
                .ToListAsync(cancellationToken);

            if (!existingResults.Any())
            {
                var resultsToSave = results.Select(r => new ScanResult
                {
                    RequestId = requestId,
                    ZAPScanId = scanRequest.ZAPScanId,
                    Severity = r.Risk,
                    Details = System.Text.Json.JsonSerializer.Serialize(r)
                }).ToList();

                await _context.ScanResults.AddRangeAsync(resultsToSave, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);
            }

            return Ok(new { Message = "SQL Injection results retrieved successfully.", Results = results });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving SQL Injection results");
            return StatusCode(500, "Failed to retrieve SQL Injection scan results.");
        }
    }






    // [HttpPut("cancel-scan/{requestId}")]
    // public async Task<IActionResult> CancelSqlInjectionScan([FromRoute] int requestId, CancellationToken cancellationToken)
    // {
    //     var scanRequest = await _context.ScanRequests.FindAsync(new object[] { requestId }, cancellationToken);

    //     if (scanRequest == null)
    //         return NotFound("Scan request not found.");

    //     if (scanRequest.Status != "In Progress")
    //         return BadRequest("Only in-progress scans can be canceled.");

    //     try
    //     {
    //         await _sqlInjectionService.CancelScanAsync((int)scanRequest.ZAPScanId);
    //         scanRequest.Status = "Canceled";
    //         scanRequest.CompletedAt = DateTime.UtcNow;
    //         await _context.SaveChangesAsync(cancellationToken);

    //         return Ok(new { Message = "SQL Injection scan canceled successfully." });
    //     }
    //     catch (Exception ex)
    //     {
    //         _logger.LogError(ex, "Error canceling scan");
    //         return StatusCode(500, "Failed to cancel the scan.");
    //     }
    // }






    // [HttpGet("sql-report/{requestId}")]
    // public async Task<IActionResult> GenerateSqlInjectionReport([FromRoute] int requestId, CancellationToken cancellationToken)
    // {
    //     var results = await _context.ScanResults
    //         .Where(r => r.RequestId == requestId)
    //         .Include(r => r.Vulnerability)
    //         .Include(r => r.ScanRequest)
    //             .ThenInclude(sr => sr.Website)
    //         .ToListAsync(cancellationToken);

    //     if (!results.Any())
    //         return NotFound("No results found for the specified request ID.");

    //     using var memoryStream = new MemoryStream();
    //     var document = new Document(PageSize.A4, 40, 40, 60, 40);
    //     var writer = PdfWriter.GetInstance(document, memoryStream);
    //     document.Open();

    //     // Fonts and colors
    //     var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16, new BaseColor(33, 37, 41));
    //     var sectionFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 12, new BaseColor(52, 58, 64));
    //     var bodyFont = FontFactory.GetFont(FontFactory.HELVETICA, 10, new BaseColor(73, 80, 87));

    //     var accentColor = new BaseColor(108, 117, 125);
    //     var lowSeverity = new BaseColor(111, 207, 151);
    //     var mediumSeverity = new BaseColor(255, 193, 7);
    //     var highSeverity = new BaseColor(220, 53, 69);
    //     var cardBackground = new BaseColor(248, 249, 250);

    //     // Header
    //     var title = new Paragraph("SQL Injection Scan Report", titleFont)
    //     {
    //         Alignment = Element.ALIGN_CENTER,
    //         SpacingAfter = 20
    //     };
    //     document.Add(title);

    //     // Summary
    //     var scan = results.First().ScanRequest;
    //     var summaryTable = new PdfPTable(1) { WidthPercentage = 100 };
    //     var summaryCell = new PdfPCell
    //     {
    //         BorderColor = accentColor,
    //         BorderWidth = 1,
    //         BackgroundColor = cardBackground,
    //         Padding = 10
    //     };
    //     var summaryParagraph = new Paragraph
    //     {
    //         new Chunk("Scan Summary\n", sectionFont),
    //         new Phrase($"Website: {scan.Website.Url}\n", bodyFont),
    //         new Phrase($"Scan Date: {scan.StartedAt:yyyy-MM-dd HH:mm}\n", bodyFont),
    //         new Phrase($"Total Vulnerabilities Found: {results.Count}\n", bodyFont)
    //     };
    //     summaryCell.AddElement(summaryParagraph);
    //     summaryTable.AddCell(summaryCell);
    //     document.Add(summaryTable);

    //     document.Add(new Paragraph(" ", bodyFont)); // spacer

    //     // Findings section
    //     var findingsTitle = new Paragraph("Vulnerability Findings", sectionFont)
    //     {
    //         SpacingBefore = 10,
    //         SpacingAfter = 10
    //     };
    //     document.Add(findingsTitle);

    //     foreach (var result in results)
    //     {
    //         var cardTable = new PdfPTable(1) { WidthPercentage = 100 };
    //         var cardCell = new PdfPCell
    //         {
    //             BorderColor = accentColor,
    //             BorderWidth = 1,
    //             BackgroundColor = cardBackground,
    //             Padding = 12
    //         };

    //         BaseColor severityColor = result.Severity switch
    //         {
    //             "High" => highSeverity,
    //             "Medium" => mediumSeverity,
    //             "Low" => lowSeverity,
    //             _ => accentColor
    //         };

    //         var severityBar = new PdfPTable(1) { WidthPercentage = 100 };
    //         var severityCell = new PdfPCell(new Phrase(" "))
    //         {
    //             BackgroundColor = severityColor,
    //             FixedHeight = 4,
    //             Border = Rectangle.NO_BORDER
    //         };
    //         severityBar.AddCell(severityCell);
    //         cardCell.AddElement(severityBar);

    //         // var details = System.Text.Json.JsonSerializer.Deserialize<SqlScanResultDto>(result.Details ?? "{}");
    //         var details = System.Text.Json.JsonSerializer.Deserialize<SqlInjectionResult>(result.Details ?? "{}");


    //         var findingParagraph = new Paragraph { SpacingBefore = 8 };
    //         findingParagraph.Add(new Chunk("Vulnerability Type: ", sectionFont));
    //         findingParagraph.Add(new Phrase("SQL Injection\n", bodyFont));

    //         findingParagraph.Add(new Chunk("Severity: ", sectionFont));
    //         findingParagraph.Add(new Phrase($"{result.Severity ?? "Unknown"}\n", bodyFont));

    //         if (details != null)
    //         {
    //             findingParagraph.Add(new Chunk("URL: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.Url}\n", bodyFont));

    //             findingParagraph.Add(new Chunk("Parameter: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.Parameter}\n", bodyFont));

    //             findingParagraph.Add(new Chunk("Payload: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.Payload}\n", bodyFont));

    //             findingParagraph.Add(new Chunk("Input Vector: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.InputVector}\n", bodyFont));

    //             findingParagraph.Add(new Chunk("Evidence: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.Evidence}\n", bodyFont));

    //             findingParagraph.Add(new Chunk("Description: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.Description}\n", bodyFont));

    //             findingParagraph.Add(new Chunk("Solution: ", sectionFont));
    //             findingParagraph.Add(new Phrase($"{details.Solution}\n", bodyFont));
    //         }

    //         cardCell.AddElement(findingParagraph);
    //         cardTable.AddCell(cardCell);
    //         document.Add(cardTable);
    //         document.Add(new Paragraph(" ", bodyFont)); // spacer
    //     }

    //     document.Close();
    //     var pdfBytes = memoryStream.ToArray();
    //     var fileName = $"sql-injection-report-{requestId}.pdf";
    //     return File(pdfBytes, "application/pdf", fileName);
    // }



    [HttpGet("sql-report/{requestId}")]
public async Task<IActionResult> GenerateSqlInjectionReport([FromRoute] int requestId, CancellationToken cancellationToken)
{
    var scan = await _context.ScanRequests
        .Include(sr => sr.Website)
        .FirstOrDefaultAsync(sr => sr.RequestId == requestId, cancellationToken);

    if (scan == null)
        return NotFound("Scan request not found.");

    var results = await _context.ScanResults
        .Where(r => r.RequestId == requestId)
        .Include(r => r.Vulnerability)
        .ToListAsync(cancellationToken);

    using var memoryStream = new MemoryStream();
    var document = new Document(PageSize.A4, 40, 40, 60, 40);
    var writer = PdfWriter.GetInstance(document, memoryStream);
    document.Open();

    // Fonts and Colors
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

    // Summary
    var summaryTable = new PdfPTable(1) { WidthPercentage = 100 };
    var summaryCell = new PdfPCell
    {
        BorderColor = accentColor,
        BorderWidth = 1,
        BackgroundColor = cardBackground,
        Padding = 10
    };

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

    // Findings Section
    var findingsTitle = new Paragraph("Vulnerability Findings", sectionFont)
    {
        SpacingBefore = 10,
        SpacingAfter = 10
    };
    document.Add(findingsTitle);

    if (!results.Any())
    {
        var noVulnParagraph = new Paragraph("No SQL Injection vulnerabilities were found for this scan.", bodyFont)
        {
            SpacingBefore = 10,
            SpacingAfter = 10,
            Alignment = Element.ALIGN_LEFT
        };
        document.Add(noVulnParagraph);
    }
    else
    {
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

            BaseColor severityColor = result.Severity switch
            {
                "High" => highSeverity,
                "Medium" => mediumSeverity,
                "Low" => lowSeverity,
                _ => accentColor
            };

            // Severity Bar
            var severityBar = new PdfPTable(1) { WidthPercentage = 100 };
            var severityCell = new PdfPCell(new Phrase(" "))
            {
                BackgroundColor = severityColor,
                FixedHeight = 4,
                Border = Rectangle.NO_BORDER
            };
            severityBar.AddCell(severityCell);
            cardCell.AddElement(severityBar);

            // Deserialize details
            var details = System.Text.Json.JsonSerializer.Deserialize<SqlInjectionResult>(result.Details ?? "{}");

            var findingParagraph = new Paragraph { SpacingBefore = 8 };
            findingParagraph.Add(new Chunk("Vulnerability Type: ", sectionFont));
            findingParagraph.Add(new Phrase("SQL Injection\n", bodyFont));

            findingParagraph.Add(new Chunk("Severity: ", sectionFont));
            findingParagraph.Add(new Phrase($"{result.Severity ?? "Unknown"}\n", bodyFont));

            if (details != null)
            {
                findingParagraph.Add(new Chunk("URL: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.Url}\n", bodyFont));

                findingParagraph.Add(new Chunk("Parameter: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.Parameter}\n", bodyFont));

                findingParagraph.Add(new Chunk("Payload: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.Payload}\n", bodyFont));

                findingParagraph.Add(new Chunk("Input Vector: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.InputVector}\n", bodyFont));

                findingParagraph.Add(new Chunk("Evidence: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.Evidence}\n", bodyFont));

                findingParagraph.Add(new Chunk("Description: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.Description}\n", bodyFont));

                findingParagraph.Add(new Chunk("Solution: ", sectionFont));
                findingParagraph.Add(new Phrase($"{details.Solution}\n", bodyFont));
            }

            cardCell.AddElement(findingParagraph);
            cardTable.AddCell(cardCell);
            document.Add(cardTable);
            document.Add(new Paragraph(" ", bodyFont)); // Spacer
        }
    }

    document.Close();
    var pdfBytes = memoryStream.ToArray();
    var fileName = $"sql-injection-report-{requestId}.pdf";
    return File(pdfBytes, "application/pdf", fileName);
}

}
