using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System;
using System.Threading.Tasks;
using Api.Helpers;
using Api.Models;
using Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// JWT configuration
var jwtSettings = new JWT
{
    Key = builder.Configuration["JWT:Key"],
    Issuer = builder.Configuration["JWT:Issuer"],
    Audience = builder.Configuration["JWT:Audience"]
};

// Make sure to set these required properties directly
builder.Services.Configure<JWT>(options =>
{
    options.Key = jwtSettings.Key;
    options.Issuer = jwtSettings.Issuer;
    options.Audience = jwtSettings.Audience;
    options.DurationInDays = Convert.ToDouble(builder.Configuration["JWT:DurationInDays"] ?? "1");
});

// Add Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApiContext>()
    .AddDefaultTokenProviders();

// Add Authentication and JWT Bearer configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(o =>
{
    o.RequireHttpsMetadata = true;
    o.SaveToken = true;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key))
    };
});

// Add CORS policy
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        builder =>
        {
            builder.WithOrigins("http://localhost:3000") // Your frontend URL
                   .AllowAnyHeader()
                   .AllowAnyMethod();
        });
});

// Configure Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Database configuration
builder.Services.AddDbContext<ApiContext>(options =>
    options.UseMySql(
        builder.Configuration.GetConnectionString("Api"),
        ServerVersion.AutoDetect(builder.Configuration.GetConnectionString("Api"))
    )
);

// Ensure unauthorized response instead of redirecting to login
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});

// Services for authorization
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Apply the CORS policy globally
app.UseCors("AllowSpecificOrigin");

// Ensure this is before UseAuthorization
app.UseAuthentication();
app.UseAuthorization();

// Map controllers
app.MapControllers();

app.Run();



// using Microsoft.AspNetCore.Authentication.JwtBearer;
// using Microsoft.AspNetCore.Builder;
// using Microsoft.AspNetCore.Hosting;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.DependencyInjection;
// using Microsoft.Extensions.Hosting;
// using Microsoft.IdentityModel.Tokens;
// using Microsoft.OpenApi.Models;
// using System.Text;
// using System;
// using Api.Helpers;
// using Api.Models;
// using Api.Services;

// var builder = WebApplication.CreateBuilder(args);

// // Add services to the container.
// builder.Services.AddControllers();

// //Jwt configuration
// builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
// builder.Services.AddAuthentication(options =>
// {
//     options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//     options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
//     options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme; // Add this line
// })
// .AddJwtBearer(o =>
// {
//     o.RequireHttpsMetadata = true;
//     o.SaveToken = true;

//     o.TokenValidationParameters = new TokenValidationParameters
//     {
//         ValidateIssuer = true,
//         ValidateAudience = true,
//         ValidateLifetime = true,
//         ValidateIssuerSigningKey = true,
//         ValidIssuer = builder.Configuration["JWT:Issuer"],
//         ValidAudience = builder.Configuration["JWT:Audience"],
//         IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
//     };
// });





// // builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
// // builder.Services.AddAuthentication(options => {
// //     options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
// //     options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
// // })
// // .AddJwtBearer(o =>
// // {
// //     o.RequireHttpsMetadata = false;
// //     o.SaveToken = false;
// //     o.TokenValidationParameters = new TokenValidationParameters
// //     {
// //         ValidateIssuerSigningKey = true,
// //         ValidateIssuer = true,
// //         ValidateAudience = true,
// //         ValidateLifetime = true,
// //         ValidIssuer = builder.Configuration["JWT:Issuer"],
// //         ValidAudience = builder.Configuration["JWT:Audience"],
// //         IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
// //     };

// //     // Log any authentication issues
// //     o.Events = new JwtBearerEvents
// //     {
// //         OnAuthenticationFailed = context =>
// //         {
// //             Console.WriteLine("JWT authentication failed:", context.Exception.Message);
// //             return Task.CompletedTask;
// //         }
// //     };
// // });

// // Identity
// builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
//     .AddEntityFrameworkStores<ApiContext>();

    

// // Services for authorization
// builder.Services.AddScoped<IAuthService, AuthService>();

// // Add CORS policy
// builder.Services.AddCors(options =>
// {
//     options.AddPolicy("AllowSpecificOrigin",
//         builder =>
//         {
//             builder.WithOrigins("http://localhost:3000") // Your frontend URL
//                    .AllowAnyHeader()
//                    .AllowAnyMethod();
//         });
// });

// // builder.Services.AddCors(options =>
// // {
// //     options.AddPolicy("AllowSpecificOrigin",
// //         builder =>
// //         {
// //             builder.WithOrigins("http://localhost:3000") // Allow your frontend URL
// //                    .AllowAnyHeader()
// //                    .AllowAnyMethod();
// //         });
// // });

// builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen();

// // Use builder.Configuration instead of Configuration. (connection string)
// builder.Services.AddDbContext<ApiContext>(options =>
//     options.UseMySql(
//         builder.Configuration.GetConnectionString("Api"),
//         ServerVersion.AutoDetect(builder.Configuration.GetConnectionString("Api"))
//     )
// );


// builder.Services.ConfigureApplicationCookie(options =>
// {
//     options.Events.OnRedirectToLogin = context =>
//     {
//         context.Response.StatusCode = StatusCodes.Status401Unauthorized;
//         return Task.CompletedTask;
//     };
// });



// var app = builder.Build();

// // Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
//     app.UseSwagger();
//     app.UseSwaggerUI();
// }

// app.UseHttpsRedirection();

// // Apply the CORS policy globally
// app.UseCors("AllowSpecificOrigin");

// // Ensure this is before UseAuthorization
// app.UseAuthentication();
// app.UseAuthorization();


// // Map controllers
// app.MapControllers();

// app.Run();
