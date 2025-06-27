using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Linq;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using Microsoft.AspNetCore.Identity;


namespace Api.Controllers
{
   
   // [Authorize ] 
   /// <summary>
    /// Controller for handling user authentication and protected resources.
    /// </summary>
    [Route("api/")]
     [ApiController]

    public class HomeController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment; 
        private readonly UserManager<ApplicationUser> _userManager; // Add this field

       // Update the constructor to include UserManager
public HomeController(IAuthService authService, ApiContext context, IWebHostEnvironment webHostEnvironment, UserManager<ApplicationUser> userManager)
{
    _authService = authService;
    _context = context;
    _webHostEnvironment = webHostEnvironment;
    _userManager = userManager; // Add this line
}
       

    [HttpGet("health")]
        public IActionResult HealthCheck()
        {
            var response = new
            {
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                message = "success"
            };

            return Ok(response);
        }


/// <summary>
        /// Register a new user.
        /// </summary>
        /// <remarks>
        /// **Route**: `POST /api/home/register`  
        /// **Purpose**:  
        /// - Handles user registration.  
        /// - Validates the model using `ModelState`.  
        /// - Calls the `RegisterAsync` method from the `IAuthService` to create a new user.  
        ///
        /// **Request Body**:  
        /// A `RegisterModel` instance with the following fields:  
        /// - `FirstName` (string, required)  
        /// - `LastName` (string, required)  
        /// - `Username` (string, required)  
        /// - `Email` (string, required)  
        /// - `Password` (string, required)  
        /// - `Gender` (string, optional)  
        /// - `Image` (binary, optional)  
        ///
        /// **Responses**:  
        /// - `200 OK`: Registration successful.  
        /// - `400 Bad Request`: Invalid model or registration failed.  
        /// </remarks>
        
[HttpPost("users")]
public async Task<IActionResult> RegisterAsync([FromForm] RegisterModel model)
{
    try
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var result = await _authService.RegisterAsync(model);

        if (!result.IsAuthenticated)
            return BadRequest(result.Message);

        return Ok(result);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error in RegisterAsync: {ex.Message}");
        return StatusCode(500, $"Internal server error: {ex.Message}");
    }
}
//         [HttpPost("users")]
// public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
// {
//     if (!ModelState.IsValid)
//         return BadRequest(ModelState);

//     var result = await _authService.RegisterAsync(model);

//     if (!result.IsAuthenticated)
//         return BadRequest(result.Message);

//     return Ok(result);
// }


         /// <summary>
        /// Log in an existing user.
        /// </summary>
        /// <remarks>
        /// **Route**: `POST /api/home/login`  
        /// **Purpose**:  
        /// - Authenticates a user and generates a JWT.  
        /// - Validates the model using `ModelState`.  
        /// - Calls the `GetTokenAsync` method from the `IAuthService` to generate a token.  
        ///
        /// **Request Body**:  
        /// A `TokenRequestModel` instance with the following fields:  
        /// - `Username` (string, required)  
        /// - `Password` (string, required)  
        ///
        /// **Responses**:  
        /// - `200 OK`: Login successful with authentication token.  
        /// - `400 Bad Request`: Invalid model or login failed.  
        /// </remarks>
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

        /// <summary>
        /// Assign a role to a user.
        /// </summary>
        /// <remarks>
        /// **Route**: `POST /api/home/addrole`  
        /// **Purpose**:  
        /// - Assigns a role to a user.  
        /// - Validates the model using `ModelState`.  
        /// - Calls the `AddRoleAsync` method from the `IAuthService` to add a role.  
        ///
        /// **Request Body**:  
        /// An `AddRoleModel` instance with the following fields:  
        /// - `Username` (string, required)  
        /// - `Role` (string, required)  
        ///
        /// **Responses**:  
        /// - `200 OK`: Role successfully assigned.  
        /// - `400 Bad Request`: Invalid model or role assignment failed.  
        /// </remarks>
        /// 
        
        // [HttpPost("addrole")]
        // public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        // {
        //     if (!ModelState.IsValid)
        //         return BadRequest(ModelState);

        //     var result = await _authService.AddRoleAsync(model);

        //     if (!string.IsNullOrEmpty(result))
        //         return BadRequest(result);

        //     return Ok(model);
        // }

       /// <summary>
        /// Retrieve a protected resource.
        /// </summary>
        /// <remarks>
        /// **Route**: `GET /api/home/protected`  
        /// **Authorization**: Requires the `User` role (`[Authorize(Roles = "User")]`).  
        ///
        /// **Purpose**:  
        /// - A protected endpoint accessible only to authenticated users with the `User` role.  
        ///
        /// **Responses**:  
        /// - `200 OK`: Protected resource retrieved successfully.  
        /// - `401 Unauthorized`: User not logged in or does not have the required role.  
        /// </remarks>
        [Authorize(Roles = "User")]
        [HttpGet("")]
        public IActionResult GetProtectedResource()
        {
            return Ok(new { message = "This is a protected resource!" });
        }
// Add this model within the HomeController.cs file since we can't add new entities
public class UpdateProfileModel
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? Gender { get; set; }
    public IFormFile? Image { get; set; }
}

[Authorize]
[HttpGet("profile")]
public async Task<IActionResult> GetProfile()
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (userId == null)
        return Unauthorized();

    var user = await _context.ApplicationUsers.FindAsync(userId);
    if (user == null)
        return NotFound("User not found");

    var profile = new
    {
        user.FirstName,
        user.LastName,
        user.UserName,
        user.Email,
        user.Gender,
        Image = user.Image != null ? $"data:image/jpeg;base64,{Convert.ToBase64String(user.Image)}" : null
    };

    return Ok(profile);
}

        [Authorize]
        [HttpPost("profile")]
        public async Task<IActionResult> UpdateProfile([FromForm] UpdateProfileModel model)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return Unauthorized();

            var user = await _context.ApplicationUsers.FindAsync(userId);
            if (user == null)
                return NotFound("User not found");

            // Update fields only if provided
            if (!string.IsNullOrEmpty(model.FirstName))
                user.FirstName = model.FirstName;
            if (!string.IsNullOrEmpty(model.LastName))
                user.LastName = model.LastName;
            if (!string.IsNullOrEmpty(model.Username))
                user.UserName = model.Username;
            if (!string.IsNullOrEmpty(model.Email))
                user.Email = model.Email;
            if (!string.IsNullOrEmpty(model.Gender))
                user.Gender = model.Gender;
            if (model.Image != null)
            {
                using (var memoryStream = new MemoryStream())
                {
                    await model.Image.CopyToAsync(memoryStream);
                    user.Image = memoryStream.ToArray();
                }
            }

            await _context.SaveChangesAsync();
            return Ok(new { message = "Profile updated successfully" });
        }

[Authorize]
[HttpPost("profile/password")]
public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
{
    try
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound("User not found");

        // Remove existing password
        var removeResult = await _userManager.RemovePasswordAsync(user);
        if (!removeResult.Succeeded)
        {
            var errors = string.Join(".", removeResult.Errors.Select(e => e.Description));
            return BadRequest(new { message = $"Failed to remove password: {errors}" });
        }

        // Add new password
        var addResult = await _userManager.AddPasswordAsync(user, model.Password);
        if (!addResult.Succeeded)
        {
            var errors = string.Empty;
            foreach (var error in addResult.Errors)
            {
                if (error.Code.Contains("Password"))
                {
                    errors += "Password must meet the following requirements: minimum 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character.";
                }
                else
                {
                    errors += $"{error.Description},";
                }
            }
            return BadRequest(new { message = errors.TrimEnd(',') });
        }

        return Ok(new { message = "Password updated successfully" });
    }
    catch (Exception ex)
    {
        return StatusCode(500, new { message = $"An error occurred: {ex.Message}" });
    }
}

// Updated model
public class ChangePasswordModel
{
    public string Password { get; set; }
}

    }
}





// using Microsoft.AspNetCore.Mvc;
// using System.Threading.Tasks;
// using Api.Models;
// using Api.Services;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.EntityFrameworkCore;
// using System.Security.Claims;
// using System.Linq;


// namespace Api.Controllers
// {
   
//    // [Authorize ] 
//    /// <summary>
//     /// Controller for handling user authentication and protected resources.
//     /// </summary>
//     [Route("api/")]
//      [ApiController]

//     public class HomeController : ControllerBase
//     {
//         private readonly IAuthService _authService;
//         private readonly ApiContext _context;
//         private readonly IWebHostEnvironment _webHostEnvironment; 

//         public HomeController(IAuthService authService,ApiContext context, IWebHostEnvironment webHostEnvironment)
//         {
//             _authService = authService;
//             _context = context ;
//             _webHostEnvironment = webHostEnvironment;
//         }
       

//     [HttpGet("health")]
//         public IActionResult HealthCheck()
//         {
//             var response = new
//             {
//                 timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
//                 message = "success"
//             };

//             return Ok(response);
//         }


// /// <summary>
//         /// Register a new user.
//         /// </summary>
//         /// <remarks>
//         /// **Route**: `POST /api/home/register`  
//         /// **Purpose**:  
//         /// - Handles user registration.  
//         /// - Validates the model using `ModelState`.  
//         /// - Calls the `RegisterAsync` method from the `IAuthService` to create a new user.  
//         ///
//         /// **Request Body**:  
//         /// A `RegisterModel` instance with the following fields:  
//         /// - `FirstName` (string, required)  
//         /// - `LastName` (string, required)  
//         /// - `Username` (string, required)  
//         /// - `Email` (string, required)  
//         /// - `Password` (string, required)  
//         /// - `Gender` (string, optional)  
//         /// - `Image` (binary, optional)  
//         ///
//         /// **Responses**:  
//         /// - `200 OK`: Registration successful.  
//         /// - `400 Bad Request`: Invalid model or registration failed.  
//         /// </remarks>
        
//     [HttpPost("users")]
// public async Task<IActionResult> RegisterAsync([FromForm] RegisterModel model)
// {
//     if (!ModelState.IsValid)
//         return BadRequest(ModelState);

//     string? imagePath = null; // Explicitly nullable

//     // Handle image upload
//     if (model.Image != null)
//     {
//         var uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "uploads");
//         Directory.CreateDirectory(uploadsFolder); // Ensure the directory exists

//         string uniqueFileName = $"{Guid.NewGuid()}_{model.Image.FileName}";
//         imagePath = Path.Combine(uploadsFolder, uniqueFileName);

//         using (var fileStream = new FileStream(imagePath, FileMode.Create))
//         {
//             await model.Image.CopyToAsync(fileStream);
//         }

        
//     }

//     var result = await _authService.RegisterAsync(model);

//     if (!result.IsAuthenticated)
//         return BadRequest(result.Message);

//     return Ok(result);
// }


// //         [HttpPost("users")]
// // public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
// // {
// //     if (!ModelState.IsValid)
// //         return BadRequest(ModelState);

// //     var result = await _authService.RegisterAsync(model);

// //     if (!result.IsAuthenticated)
// //         return BadRequest(result.Message);

// //     return Ok(result);
// // }


//          /// <summary>
//         /// Log in an existing user.
//         /// </summary>
//         /// <remarks>
//         /// **Route**: `POST /api/home/login`  
//         /// **Purpose**:  
//         /// - Authenticates a user and generates a JWT.  
//         /// - Validates the model using `ModelState`.  
//         /// - Calls the `GetTokenAsync` method from the `IAuthService` to generate a token.  
//         ///
//         /// **Request Body**:  
//         /// A `TokenRequestModel` instance with the following fields:  
//         /// - `Username` (string, required)  
//         /// - `Password` (string, required)  
//         ///
//         /// **Responses**:  
//         /// - `200 OK`: Login successful with authentication token.  
//         /// - `400 Bad Request`: Invalid model or login failed.  
//         /// </remarks>
//         [HttpPost("login")]
//         public async Task<IActionResult> LoginAsync([FromBody] TokenRequestModel model)
//         {
//             if (!ModelState.IsValid)
//                 return BadRequest(ModelState);

//             var result = await _authService.GetTokenAsync(model);

//             if (!result.IsAuthenticated)
//                 return BadRequest(result.Message);

//             return Ok(result);
//         }

//         /// <summary>
//         /// Assign a role to a user.
//         /// </summary>
//         /// <remarks>
//         /// **Route**: `POST /api/home/addrole`  
//         /// **Purpose**:  
//         /// - Assigns a role to a user.  
//         /// - Validates the model using `ModelState`.  
//         /// - Calls the `AddRoleAsync` method from the `IAuthService` to add a role.  
//         ///
//         /// **Request Body**:  
//         /// An `AddRoleModel` instance with the following fields:  
//         /// - `Username` (string, required)  
//         /// - `Role` (string, required)  
//         ///
//         /// **Responses**:  
//         /// - `200 OK`: Role successfully assigned.  
//         /// - `400 Bad Request`: Invalid model or role assignment failed.  
//         /// </remarks>
//         /// 
        
//         // [HttpPost("addrole")]
//         // public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
//         // {
//         //     if (!ModelState.IsValid)
//         //         return BadRequest(ModelState);

//         //     var result = await _authService.AddRoleAsync(model);

//         //     if (!string.IsNullOrEmpty(result))
//         //         return BadRequest(result);

//         //     return Ok(model);
//         // }

//        /// <summary>
//         /// Retrieve a protected resource.
//         /// </summary>
//         /// <remarks>
//         /// **Route**: `GET /api/home/protected`  
//         /// **Authorization**: Requires the `User` role (`[Authorize(Roles = "User")]`).  
//         ///
//         /// **Purpose**:  
//         /// - A protected endpoint accessible only to authenticated users with the `User` role.  
//         ///
//         /// **Responses**:  
//         /// - `200 OK`: Protected resource retrieved successfully.  
//         /// - `401 Unauthorized`: User not logged in or does not have the required role.  
//         /// </remarks>
//         [Authorize(Roles = "User")]
//         [HttpGet("")]
//         public IActionResult GetProtectedResource()
//         {
//             return Ok(new { message = "This is a protected resource!" });
//         }




//     }
// }



