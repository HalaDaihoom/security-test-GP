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
        {
            return BadRequest("User ID not found.");
        }

        model.UserId = userId;
        model.CreatedAt = DateTime.UtcNow;

        _context.Websites.Add(model);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(AutomaticScanner), new { id = model.WebsiteId }, model);
    }
    }
}