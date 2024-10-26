

using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

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
            // Call the base OnModelCreating to configure Identity-related tables
            base.OnModelCreating(modelBuilder);

            // (Optional) Add additional configurations for relationships if needed
         
        }
    }
}




/*using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;



namespace Api.Models {

    public class ApiContext : IdentityDbContext<ApplicationUser>
    {
         public ApiContext() { }

            public ApiContext(DbContextOptions<ApiContext> options)
              : base(options)
         {

         }

    //      protected override void OnModelCreating(ModelBuilder modelBuilder)
    //     {
    //         base.OnModelCreating(modelBuilder);
    //     }
    
    
    // public DbSet<User> Users { get; set; }

   
}
}*/