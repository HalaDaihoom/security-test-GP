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
   /// <summary>
    /// Controller for handling user authentication and protected resources.
    /// </summary>
    [Route("api/")]
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
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromForm] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.RegisterAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

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
        [HttpGet("protected")]
        public IActionResult GetProtectedResource()
        {
            return Ok(new { message = "This is a protected resource!" });
        }




    }
}



