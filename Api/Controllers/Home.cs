using Microsoft.AspNetCore.Mvc;
using Api.Models;
namespace Api.Controllers;

[ApiController]
[Route("[controller]")]
public class Home : ControllerBase
{
    private readonly ApiContext _context;

    public Home(ApiContext context)
    {
        _context = context;
    }

    [HttpPost]
    public IActionResult login([FromBody]User body){
        var user=_context.User.FirstOrDefault(u=>u.Email==body.Email && u.Password==body.Password);

        if(user == null){
            return Unauthorized(new { message = "Invalid username or password" }); 
        }
        
        return Ok(new {message="login successed"});
    }
    
    
}
