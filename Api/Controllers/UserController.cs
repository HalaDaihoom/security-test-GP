

// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.EntityFrameworkCore;
// using System.Security.Claims;
// using Api.Models;
// using Microsoft.Extensions.Logging;
// using Api.Services;
// using Newtonsoft.Json;

// namespace Api.Controllers
// {
//     [Authorize(Roles = "User")]
//     [Route("api/[controller]")]
//     [ApiController]
//     public class UserController : ControllerBase
//     {
//         private readonly IAuthService _authService;
//         private readonly ApiContext _context;
//         private readonly ZapService _zapService;
//         private readonly ILogger<UserController> _logger;

//         public UserController(IAuthService authService, ApiContext context, ZapService zapService, ILogger<UserController> logger)
//         {
//             _authService = authService;
//             _context = context;
//             _zapService = zapService;
//             _logger = logger;
//         }

// [HttpPost("automatic-scanner")]
// public async Task<IActionResult> AutomaticScanner([FromBody] Website model, CancellationToken cancellationToken)
// {
//     if (model == null || !ModelState.IsValid)
//         return BadRequest(ModelState);

//     var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
//     if (string.IsNullOrEmpty(userId))
//         return BadRequest("User ID not found.");

//     // Initialize Website entry
//     model.UserId = userId;
//     model.CreatedAt = DateTime.UtcNow;

//     _context.Websites.Add(model);
//     await _context.SaveChangesAsync(cancellationToken);

//     // Initialize ScanRequest entry
//     var scanRequest = new ScanRequest
//     {
//         UserId = userId,
//         WebsiteId = model.WebsiteId,
//         Status = "In Progress",
//         StartedAt = DateTime.UtcNow
//     };

//     _context.ScanRequests.Add(scanRequest);
//     await _context.SaveChangesAsync(cancellationToken);

//     string spiderId;
//     try
//     {
//         spiderId = await _zapService.StartSpiderAsync(model.Url, cancellationToken);
//     }
//     catch (Exception ex)
//     {
//         return StatusCode(500, $"Error starting ZAP spider: {ex.Message}");
//     }

//     string spiderStatus;
//     do
//     {
//         await Task.Delay(5000, cancellationToken);
//         spiderStatus = await _zapService.GetSpiderStatusAsync(spiderId, cancellationToken);
//         _logger.LogInformation($"Spider status: {spiderStatus}");
//     } while (spiderStatus != "100");

//     string scanId;
//     try
//     {
//         scanId = await _zapService.StartScanAsync(model.Url, cancellationToken);
//         scanRequest.ZAPScanId = scanId; // Store the ScanId from ZAP
//         await _context.SaveChangesAsync(cancellationToken);
//     }
//     catch (Exception ex)
//     {
//         return StatusCode(500, $"Error starting ZAP scan: {ex.Message}");
//     }

//     string scanStatus;
//     int retryCount = 0;
//     const int maxRetries = 60; // Adjust for long scans
//     const int delayMilliseconds = 5000;

//     do
//     {
//         await Task.Delay(delayMilliseconds, cancellationToken);
//         scanStatus = await _zapService.GetScanStatusAsync(scanId, cancellationToken);

//         _logger.LogInformation($"Scan status for scanId {scanId}: {scanStatus}");

//         retryCount++;
//         if (retryCount > maxRetries)
//         {
//             _logger.LogError($"Scan for scanId {scanId} timed out after {maxRetries * delayMilliseconds / 1000} seconds.");
//             return StatusCode(504, "Scan timed out. Please try again.");
//         }
//     } while (!scanStatus.Equals("100", StringComparison.OrdinalIgnoreCase) &&
//              !scanStatus.Equals("finished", StringComparison.OrdinalIgnoreCase));

//     string scanResults;
//     try
//     {
//         scanResults = await _zapService.GetScanResultsAsync(scanId, cancellationToken);
//     }
//     catch (Exception ex)
//     {
//         return StatusCode(500, $"Error retrieving scan results: {ex.Message}");
//     }

//     // Update the ScanRequest status to "Completed" and add the completion time
//     scanRequest.Status = "Completed";
//     scanRequest.CompletedAt = DateTime.UtcNow;
//     await _context.SaveChangesAsync(cancellationToken);

//     _logger.LogInformation($"ScanRequest for WebsiteId {model.WebsiteId} updated to 'Completed'.");

//     // Return a success message along with scan results
//     return Ok(new { Message = "Scan completed successfully", Results = scanResults });
// }

// }
// }

