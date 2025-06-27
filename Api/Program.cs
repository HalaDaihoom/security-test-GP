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
using Api.Services.Scanners;

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
            policy.WithOrigins("https://scan-website-front.vercel.app",
            "https://scan-website-front-hala-daihooms-projects.vercel.app",
            "http://localhost:3000" )
                   .AllowAnyHeader()
                   .AllowAnyMethod()
                   .AllowCredentials(); 
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
        new MySqlServerVersion(new Version(8, 0, 21)),
        mysqlOptions =>
        {
            mysqlOptions.EnableRetryOnFailure(3, TimeSpan.FromSeconds(5), null);
        }));

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
    options.ListenAnyIP(5000); // Azure requires port 8080
    
});

builder.Services.AddMemoryCache();

// Services for authorization
builder.Services.AddScoped<IAuthService, AuthService>();

builder.Services.AddHttpClient<ZapService>();
builder.Services.AddHttpClient<XssZapService>();
builder.Services.AddScoped<SqlInjectionService>();
builder.Services.AddHttpClient<SubdomainExtractorService>();
builder.Services.AddHttpClient<SubdomainTakeoverScanner>();

builder.Services.AddScoped<SubzyTestService>();

// add to subdomain takeover
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
    logging.AddEventSourceLogger();
});

builder.Services.AddHttpClient<SubdomainTakeoverScanner>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("SubdomainScanner/1.0");
});
// Register the scanner
builder.Services.AddScoped<SubdomainTakeoverScanner>();

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

