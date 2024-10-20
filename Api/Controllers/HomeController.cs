using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Api.Models;
using Api.Services;
namespace Api.Controllers;

//[Authorize(Roles = "User")]
[ApiController]
[Route("[controller]")]
public class HomeController : ControllerBase
{
    
        private readonly IAuthService _authService;

        public HomeController(IAuthService authService)
        {
            _authService = authService;
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
    
    
}
