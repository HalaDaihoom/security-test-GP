using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Api.DTOs;
using Api.Services;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly ZapService _zapService;
        private readonly ILogger<UserController> _logger;

        public UserController(IAuthService authService, ApiContext context, ZapService zapService, ILogger<UserController> logger)
        {
            _authService = authService;
            _context = context;
            _zapService = zapService;
            _logger = logger;
        }

       [HttpPost("scanners/automatic-scanner")]
public async Task<IActionResult> AutomaticScanner([FromBody] Website model, CancellationToken cancellationToken)
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
        // Start ZAP Spider
        var spiderId = await _zapService.StartSpiderAsync(model.Url, cancellationToken);
        string spiderStatus;
        do
        {
            await Task.Delay(5000, cancellationToken);
            spiderStatus = await _zapService.GetSpiderStatusAsync(spiderId, cancellationToken);
            _logger.LogInformation($"Spider status: {spiderStatus}");
        } while (spiderStatus != "100");

        // Start ZAP Scan
        var scanId = await _zapService.StartScanAsync(model.Url, cancellationToken);
        scanRequest.ZAPScanId = scanId;
        await _context.SaveChangesAsync(cancellationToken);

        // Wait for scan to complete
        string scanStatus;
        const int maxRetries = 120;
        int retries = 0;
        do
        {
            await Task.Delay(5000, cancellationToken);
            scanStatus = await _zapService.GetScanStatusAsync(scanId, cancellationToken);
            _logger.LogInformation($"Scan status: {scanStatus}");
            retries++;
        } while (!scanStatus.Equals("100", StringComparison.OrdinalIgnoreCase) &&
                 retries < maxRetries);

        if (retries >= maxRetries)
        {
            _logger.LogError($"Scan for {scanId} timed out.");
            return StatusCode(504, "Scan timed out.");
        }

        scanRequest.Status = "Completed";
        scanRequest.CompletedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync(cancellationToken);
        _logger.LogInformation($"Returning redirectUrl: /scanner/scan-results?scanId={scanId}");

        return Ok(new
        {
            Message = "Scan completed successfully!",
            redirectUrl = $"/scanner/scan-results?scanId={scanId}"
        });
    }
    catch (Exception ex)
    {
        _logger.LogError($"Error during scan: {ex.Message}");
        return StatusCode(500, "An error occurred during the scan process.");
    }
}

[HttpGet("scanners/automatic-scanner/scan-results")]
public async Task<IActionResult> GetScanResults([FromQuery] int scanId, CancellationToken cancellationToken)
{
    try
    {
        var scanRequest = await _context.ScanRequests
            .Include(r => r.Website)
            .FirstOrDefaultAsync(r => r.ZAPScanId == scanId, cancellationToken);

        if (scanRequest == null)
            return NotFound("Scan not found.");

        string baseUrl = scanRequest.Website.Url;
        string scanResultsJson = await _zapService.GetScanResultsAsync(baseUrl, cancellationToken);

        var zapAlerts = JsonConvert.DeserializeObject<ZapAlertsDtoResponse>(scanResultsJson);

        if (zapAlerts?.Alerts == null || !zapAlerts.Alerts.Any())
        {
            return Ok(new { Message = "No vulnerabilities found.", Results = Array.Empty<ScanResult>() });
        }

        var resultsToSave = zapAlerts.Alerts.Select(alert => new ScanResult
        {
            RequestId = scanRequest.RequestId,
            Severity = alert.Risk,
            Details = JsonConvert.SerializeObject(alert)
        }).ToList();

        var existingResults = await _context.ScanResults
            .Where(r => r.RequestId == scanRequest.RequestId)
            .ToListAsync(cancellationToken);

        if (!existingResults.Any())
        {
            await _context.ScanResults.AddRangeAsync(resultsToSave, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return Ok(new { Message = "Scan results retrieved successfully.", Results = resultsToSave });
    }
    catch (Exception ex)
    {
        _logger.LogError($"Error retrieving scan results: {ex.Message}");
        return StatusCode(500, "Failed to retrieve scan results.");
    }
}

    }
}
