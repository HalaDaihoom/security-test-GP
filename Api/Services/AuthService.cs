using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Api.Helpers;
using Api.Models;

namespace Api.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
{
    if (await _userManager.FindByEmailAsync(model.Email) is not null)
        return new AuthModel { Message = "Email is already registered!" };

    if (await _userManager.FindByNameAsync(model.Username) is not null)
        return new AuthModel { Message = "Username is already registered!" };

    var user = new ApplicationUser
    {
        UserName = model.Username,
        Email = model.Email,
        FirstName = model.FirstName,
        LastName = model.LastName,
        Gender = model.Gender,
        
    };
            // Handle Image upload and convert to byte[]
            // if (model.Image != null)
            // {
            //     using (var memoryStream = new MemoryStream())
            //     {
            //         await model.Image.CopyToAsync(memoryStream);  // Copy file to memory stream
            //         user.Image = memoryStream.ToArray();  // Save the byte[] image data
            //     }
            // }
            // Handle Image upload and convert to byte[]
            if (model.Image != null)
            {
                using (var memoryStream = new MemoryStream())
                {
                    await model.Image.CopyToAsync(memoryStream);
                    user.Image = memoryStream.ToArray();
                }
            }

    var result = await _userManager.CreateAsync(user, model.Password);

    if (!result.Succeeded)
    {
        var errors = string.Empty;

         foreach (var error in result.Errors)
        {
            if (error.Code.Contains("Password"))
            {
                // Customize the error message based on password validation failures
                errors += "Password must meet the following requirements: Minimum 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character.";
            }
            else
            {
                errors += $"{error.Description},";
            }
        }

        return new AuthModel { Message = errors };
    }

    // Check if the role exists before adding it
    if (!await _roleManager.RoleExistsAsync("User"))
    {
        await _roleManager.CreateAsync(new IdentityRole("User"));
    }

    await _userManager.AddToRoleAsync(user, "User");

    var jwtSecurityToken = await CreateJwtToken(user);

    return new AuthModel
    {
        Email = user.Email,
        ExpiresOn = jwtSecurityToken.ValidTo,
        IsAuthenticated = true,
        Roles = new List<string> { "User" },
        Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
        Username = user.UserName
    };
}

//     public async Task<AuthModel> RegisterAsync(RegisterModel model)
// {
//     // Check for existing email
//     if (await _userManager.FindByEmailAsync(model.Email) is not null)
//         return new AuthModel { Message = "Email is already registered!" };

//     // Check for existing username
//     if (await _userManager.FindByNameAsync(model.Username) is not null)
//         return new AuthModel { Message = "Username is already registered!" };

//     var user = new ApplicationUser
//     {
//         UserName = model.Username,
//         Email = model.Email,
//         FirstName = model.FirstName,
//         LastName = model.LastName,
//         Gender = model.Gender,
//         Image = model.Image
//     };

//     var result = await _userManager.CreateAsync(user, model.Password);

//     // Handle registration errors
//     if (!result.Succeeded)
//     {
//         var errors = string.Join(",", result.Errors.Select(e => e.Description));
//         return new AuthModel { Message = errors };
//     }

//     // Ensure the role exists
//     if (!await _roleManager.RoleExistsAsync("User"))
//     {
//         await _roleManager.CreateAsync(new IdentityRole("User"));
//     }

//     // Assign user role
//     await _userManager.AddToRoleAsync(user, "User");

//     // Add claims for the user
//     var userClaims = new List<Claim>
//     {
//         new Claim(ClaimTypes.NameIdentifier, user.Id), // Add NameIdentifier claim
//         new Claim(ClaimTypes.Name,user.Email)
//     };

//     // Ensure the claims are added for the user
//     foreach (var claim in userClaims)
//     {
//         if (!(await _userManager.GetClaimsAsync(user)).Any(c => c.Type == claim.Type && c.Value == claim.Value))
//         {
//             await _userManager.AddClaimAsync(user, claim);
//         }
//     }

//     // Create JWT
//     var jwtSecurityToken = await CreateJwtToken(user);

//     return new AuthModel
//     {
//         Email = user.Email,
//         ExpiresOn = jwtSecurityToken.ValidTo,
//         IsAuthenticated = true,
//         Roles = new List<string> { "User" },
//         Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
//         Username = user.UserName
//     };
// }


        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }

            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }

private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
{
    var userClaims = await _userManager.GetClaimsAsync(user);
    var roles = await _userManager.GetRolesAsync(user);
    var roleClaims = roles.Select(role => new Claim(ClaimTypes.Role, role)).ToList();

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim(ClaimTypes.Name,user.Email ),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), // Add NameIdentifier claim here as well

        new Claim("uid", user.Id)
    }
    .Union(userClaims)
    .Union(roleClaims);

    var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
    var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

    var jwtSecurityToken = new JwtSecurityToken(
        issuer: _jwt.Issuer,
        audience: _jwt.Audience,
        claims: claims,
        expires: DateTime.Now.AddDays(_jwt.DurationInDays),
        signingCredentials: signingCredentials);

    return jwtSecurityToken;
}

       
    }
}