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

            // ✅ Set the database collation to UTF8MB4 (for emoji and full Unicode support)
            modelBuilder.UseCollation("utf8mb4_unicode_ci");
        }
    }
}


// using Microsoft.EntityFrameworkCore;
// using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

// namespace Api.Models
// {
//     public class ApiContext : IdentityDbContext<ApplicationUser>
//     {
//         public ApiContext() { }

//         public ApiContext(DbContextOptions<ApiContext> options)
//             : base(options)
//         {
//         }

        
//         public DbSet<ApplicationUser> ApplicationUsers { get; set; }
//           public DbSet<Website> Websites { get; set; }
//         public DbSet<ScanRequest> ScanRequests { get; set; }
//         public DbSet<Vulnerability> Vulnerabilities { get; set; }
//         public DbSet<ScanResult> ScanResults { get; set; }



//         protected override void OnModelCreating(ModelBuilder modelBuilder)
//         {
//             // Call the base OnModelCreating to configure Identity-related tables
//             base.OnModelCreating(modelBuilder);

//             // (Optional) Add additional configurations for relationships if needed
         
//         }
//     }
// }




