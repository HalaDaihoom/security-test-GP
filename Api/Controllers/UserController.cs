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

        /// <summary>
         /// Controller for handling user-related operations such as vulnerability scanning and history retrieval.
        /// </summary>

    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly ZapService _zapService;
        private readonly IWebHostEnvironment _webHostEnvironment; 

        private readonly ILogger<UserController> _logger;

        public UserController(IAuthService authService, ApiContext context, ZapService zapService,IWebHostEnvironment webHostEnvironment, ILogger<UserController> logger)
        {
            _authService = authService;
            _context = context;
            _zapService = zapService;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
        }



 /// <summary>
        /// Initiates an automatic vulnerability scan for a given website URL.
        /// </summary>
        /// <remarks>
        /// **URL**: `POST /api/scanners/automatic-scanner`  
        /// **Purpose**:  
        /// - Initiates an automatic vulnerability scan using ZAP.  
        /// - Associates the scan with the authenticated user.  
        /// - Performs a spider crawl followed by an active vulnerability scan.  
        /// - Saves the scan request and results in the database.  
        ///
        /// **Request Body**:  
        /// A `Website` instance with the following fields:  
        /// - `Url` (string, required): The website URL to scan.  
        ///
        /// **Responses**:  
        /// - `200 OK`: Scan completed successfully with a redirect URL to view the results.  
        /// - `400 Bad Request`: Invalid input or malformed URL.  
        /// - `401 Unauthorized`: User is not authenticated.  
        /// - `500 Internal Server Error`: Error during the scan process.  
        /// </remarks>

[HttpPost("scan-requests")]
public async Task<IActionResult> AutomaticScanner([FromBody] Website model, CancellationToken cancellationToken)
{
    _logger.LogInformation("Received scan request.");

    if (model == null || !ModelState.IsValid)
    {
        _logger.LogError("Invalid request received.");
        return BadRequest("Invalid request. Please provide a valid website URL.");
    }

    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
    {
        _logger.LogError("Unauthorized access - User ID not found.");
        return Unauthorized("User ID not found.");
    }

    try
    {
        _logger.LogInformation($"Starting scan for {model.Url}");

        var spiderId = await _zapService.StartSpiderAsync(model.Url, cancellationToken);
        _logger.LogInformation($"Spider started with ID {spiderId}");

        var scanId = await _zapService.StartScanAsync(model.Url, cancellationToken);
        _logger.LogInformation($"Scan started with ID {scanId}");

        return Ok(new { Message = "Scan started!", ScanId = scanId });
    }
    catch (Exception ex)
    {
        _logger.LogError($"Scan failed: {ex.Message}");
        return StatusCode(500, "Scan failed due to an internal error.");
    }
}


// [HttpPost("scan-requests")]
// public async Task<IActionResult> AutomaticScanner([FromBody] Website model, CancellationToken cancellationToken)
// {
//     if (model == null || !ModelState.IsValid)
//         return BadRequest("Invalid request. Please provide a valid website URL.");

//     var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
//     if (string.IsNullOrEmpty(userId))
//         return Unauthorized("User ID not found.");

//     model.UserId = userId;
//     model.CreatedAt = DateTime.UtcNow;

//     _context.Websites.Add(model);
//     await _context.SaveChangesAsync(cancellationToken);

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
//         // Start ZAP Spider
//         var spiderId = await _zapService.StartSpiderAsync(model.Url, cancellationToken);
//         string spiderStatus;
//         do
//         {
//             await Task.Delay(5000, cancellationToken);
//             spiderStatus = await _zapService.GetSpiderStatusAsync(spiderId, cancellationToken);
//             _logger.LogInformation($"Spider status: {spiderStatus}");
//         } while (spiderStatus != "100");

//         // Start ZAP Scan
//         var scanId = await _zapService.StartScanAsync(model.Url, cancellationToken);
//         scanRequest.ZAPScanId = scanId;
//         await _context.SaveChangesAsync(cancellationToken);

//         // Wait for scan to complete
//         string scanStatus;
//         const int maxRetries = 120;
//         int retries = 0;
//         do
//         {
//             await Task.Delay(5000, cancellationToken);
//             scanStatus = await _zapService.GetScanStatusAsync(scanId, cancellationToken);
//             _logger.LogInformation($"Scan status: {scanStatus}");
//             retries++;
//         } while (!scanStatus.Equals("100", StringComparison.OrdinalIgnoreCase) &&
//                  retries < maxRetries);

//         if (retries >= maxRetries)
//         {
//             _logger.LogError($"Scan for {scanId} timed out.");
//             return StatusCode(504, "Scan timed out.");
//         }

//         scanRequest.Status = "Completed";
//         scanRequest.CompletedAt = DateTime.UtcNow;
//         await _context.SaveChangesAsync(cancellationToken);
//         _logger.LogInformation($"Returning redirectUrl:/scanner/scan-result?scanId={scanId}");

//         return Ok(new
//         {
//             Message = "Scan completed successfully!",
//             redirectUrl = $"/scanner/scan-result?scanId={scanId}"
//         });
//     }
//     catch (Exception ex)
//     {
//         _logger.LogError($"Error during scan: {ex.Message}");
//         return StatusCode(500, "An error occurred during the scan process.");
//     }
// }
 /// <summary>
        /// Retrieves the results of a completed scan based on a scan ID.
        /// </summary>
        /// <remarks>
        /// **URL**: `GET /api/scanners/automatic-scanner/scan-results`  
        /// **Purpose**:  
        /// - Fetches scan results from ZAP for a given scan ID.  
        /// - Parses and saves the results in the database if not already present.  
        ///
        /// **Query Parameters**:  
        /// - `scanId` (int, required): The ID of the scan to retrieve results for.  
        ///
        /// **Responses**:  
        /// - `200 OK`: Scan results retrieved successfully, with details of vulnerabilities (if any).  
        /// - `404 Not Found`: No scan found for the provided ID.  
        /// - `500 Internal Server Error`: Error while retrieving scan results.  
        /// </remarks>
[HttpGet("scan-result")]
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
            ZAPScanId = scanId, // Store ZAPScanId here

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

        /// <summary>
        /// Retrieves the scan history of the authenticated user.
        /// </summary>
        /// <remarks>
        /// **URL**: `GET /api/scanners/history`  
        /// **Purpose**:  
        /// - Fetches all scans performed by the authenticated user.  
        /// - Returns details such as the website URL, start time, and ZAP scan ID.  
        ///
        /// **Responses**:  
        /// - `200 OK`: Scan history retrieved successfully.  
        /// - `401 Unauthorized`: User is not authenticated.  
        /// </remarks>
[HttpGet("scan-results")]
public async Task<IActionResult> GetScanHistory(CancellationToken cancellationToken)
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
        return Unauthorized("User ID not found.");

    var scanHistory = await _context.ScanRequests
        .Include(sr => sr.Website)
        .Where(sr => sr.UserId == userId)
        .OrderByDescending(sr => sr.StartedAt)
        .Select(sr => new
        {
            sr.Website.Url,
            sr.StartedAt,
            sr.ZAPScanId
        })
        .ToListAsync(cancellationToken);

    return Ok(scanHistory);
}

    }
}
