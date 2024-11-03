
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Linq;


namespace Api.Controllers
{
   
    [Authorize(Roles = "User")]
    [Route("api/[controller]")]
     [ApiController]

    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;

        public UserController(IAuthService authService,ApiContext context)
        {
            _authService = authService;
             _context = context ;
        }

        [HttpPost("automatic-scanner")]
public async Task<IActionResult> AutomaticScanner([FromBody] Website model)
{
    if (model == null || !ModelState.IsValid)
        return BadRequest(ModelState);

    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
        return BadRequest("User ID not found.");

    model.UserId = userId;
    model.CreatedAt = DateTime.UtcNow;

    // Save the website entry
    _context.Websites.Add(model);
    await _context.SaveChangesAsync();

    // Initiate scan with ZAP
    var zapService = HttpContext.RequestServices.GetRequiredService<ZapService>();
    string scanId;
    try
    {
        scanId = await zapService.StartScanAsync(model.Url);
    }
    catch (Exception ex)
    {
        return StatusCode(500, $"Error starting ZAP scan: {ex.Message}");
    }

    // Log the scan request in the database
    var scanRequest = new ScanRequest
    {
        UserId = userId,
        WebsiteId = model.WebsiteId,
        Status = "In Progress",
        StartedAt = DateTime.UtcNow,
    };
    _context.ScanRequests.Add(scanRequest);
    await _context.SaveChangesAsync();

    // Poll the scan status (consider implementing a background job here)
    string status;
    do
    {
        await Task.Delay(5000); // Wait for 5 seconds between checks
        status = await zapService.GetScanStatusAsync(scanId);
    } while (status != "100"); // '100' indicates completion

    // Update scan status and retrieve results
    scanRequest.Status = "Completed";
    scanRequest.CompletedAt = DateTime.UtcNow;
    string results = await zapService.GetScanResultsAsync(scanId);

    // (Optional) Process the results to store vulnerabilities in the database
    // For simplicity, you could parse and save alerts as new records in a Vulnerabilities table

    await _context.SaveChangesAsync();

    return Ok(new { Message = "Scan completed successfully", Results = results });
}

    
    }
}