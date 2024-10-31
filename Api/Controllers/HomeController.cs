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
   
   // [Authorize ] 
    [Route("api/[controller]")]
     [ApiController]

    public class HomeController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;

        public HomeController(IAuthService authService,ApiContext context)
        {
            _authService = authService;
             _context = context ;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.RegisterAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.GetTokenAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        
        [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(model);
        }

       
        [Authorize(Roles = "User")]
        [HttpGet("protected")]
        public IActionResult GetProtectedResource()
        {
            return Ok(new { message = "This is a protected resource!" });
        }





    [Authorize(Roles = "User")]
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
