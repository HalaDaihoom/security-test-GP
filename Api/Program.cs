using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System;
using System.Threading.Tasks;
using System.Text.Json.Serialization;
using Api.Helpers;
using Api.Models;
using Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
// JWT configuration
var jwtSettings = new JWT
{
    Key = builder.Configuration["JWT:Key"],
    Issuer = builder.Configuration["JWT:Issuer"],
    Audience = builder.Configuration["JWT:Audience"]
};

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
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
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
        policy =>
        {
            policy.WithOrigins("https://scan-website-front2.vercel.app",
            "https://scan-website-front2-72ukhmmcp-hala-daihooms-projects.vercel.app/")
                   .AllowAnyHeader()
                   .AllowAnyMethod()
                   .AllowCredentials(); // Allow credentials
        });
});

// Configure Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    var xmlFilename = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
});

// Database configuration


builder.Services.AddDbContext<ApiContext>(options =>
    options.UseMySql(
        builder.Configuration.GetConnectionString("Api"),
        ServerVersion.AutoDetect(builder.Configuration.GetConnectionString("Api"))
    )
);

// Add services to the container.
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.Preserve;
    });

// Ensure unauthorized response instead of redirecting to login
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8080); // Azure requires port 8080
});

// Services for authorization
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddHttpClient<ZapService>(); // Ensure this line is here

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

try
{
    app.Run();
}
catch (Exception ex)
{
    app.Logger.LogCritical(ex, "Application startup failed!");
    throw;
}
