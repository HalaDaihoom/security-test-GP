using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Api.Models
{
    public class ApiContext : IdentityDbContext<ApplicationUser>
    {
        public ApiContext() { }

        public ApiContext(DbContextOptions<ApiContext> options)
            : base(options)
        {
        }

        public DbSet<ApplicationUser> ApplicationUsers { get; set; }
        public DbSet<Website> Websites { get; set; }
        public DbSet<ScanRequest> ScanRequests { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
        public DbSet<ScanResult> ScanResults { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // ✅ Fix key length issue for MySQL (Index columns)
            modelBuilder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(u => u.NormalizedUserName).HasMaxLength(191);
                entity.Property(u => u.NormalizedEmail).HasMaxLength(191);
            });

            modelBuilder.Entity<IdentityRole>(entity =>
            {
                entity.Property(r => r.NormalizedName).HasMaxLength(191);
            });

            modelBuilder.Entity<Vulnerability>().HasData(
               new Vulnerability
               {
                   VulnerabilityId = 1,
                   VulnerabilityName = VulnerabilityTypes.ReflectedXSS,
                   Description = "Reflected Cross-Site Scripting vulnerability",
                   Category = "XSS",
                   Remediation = "Implement proper input validation and output encoding",
                   CreatedAt = DateTime.UtcNow
               },
               new Vulnerability
               {
                   VulnerabilityId = 2,
                   VulnerabilityName = VulnerabilityTypes.StoredXSS,
                   Description = "Stored Cross-Site Scripting vulnerability",
                   Category = "XSS",
                   Remediation = "Sanitize all user input before storage and encode before display",
                   CreatedAt = DateTime.UtcNow
               },
               new Vulnerability
               {
                   VulnerabilityId = 3,
                   VulnerabilityName = VulnerabilityTypes.DOMXSS,
                   Description = "DOM-based Cross-Site Scripting vulnerability",
                   Category = "XSS",
                   Remediation = "Avoid using unsafe JavaScript methods like innerHTML, document.write()",
                   CreatedAt = DateTime.UtcNow
               },
               new Vulnerability
               {
                   VulnerabilityId = 4,
                   VulnerabilityName = VulnerabilityTypes.PolyglotXSS,
                   Description = "Polyglot XSS payload that works in multiple contexts",
                   Category = "XSS",
                   Remediation = "Implement context-aware output encoding",
                   CreatedAt = DateTime.UtcNow
               },
               new Vulnerability
               {
                   VulnerabilityId = 5,
                   VulnerabilityName = VulnerabilityTypes.WAFBypassXSS,
                   Description = "XSS payload designed to bypass Web Application Firewalls",
                   Category = "XSS",
                   Remediation = "Implement multiple layers of defense and regular WAF rule updates",
                   CreatedAt = DateTime.UtcNow
               });

            modelBuilder.UseCollation("utf8mb4_unicode_ci");
        }
    }
}



