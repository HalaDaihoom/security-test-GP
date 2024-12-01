using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly HttpClient _httpClient;
        private readonly ZapService _zapService;

        public UserController(IAuthService authService, ApiContext context, HttpClient httpClient, ZapService zapService)
        {
            _authService = authService;
            _context = context;
            _httpClient = httpClient;
            _zapService = zapService;
        }

        [HttpPost("automatic-scanner")]
        public async Task<IActionResult> AutomaticScanner([FromBody] Website model)
        {
            if (model == null || !ModelState.IsValid)
                return BadRequest(ModelState);

            // Retrieve the user ID from the token (authentication)
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("User ID not found.");
            }

            // Store the website URL in the database
            model.UserId = userId;
            model.CreatedAt = DateTime.UtcNow;

            _context.Websites.Add(model);
            await _context.SaveChangesAsync();

            // Trigger ZAP scan after saving the URL in the database
            var scanId = await _zapService.StartScanAsync(model.Url);

            if (string.IsNullOrEmpty(scanId))
            {
                return StatusCode(500, "Error triggering ZAP scan.");
            }

            // Return success if the scan is triggered successfully
            return CreatedAtAction(nameof(AutomaticScanner), new { id = model.WebsiteId }, model);
        }
    }
}



