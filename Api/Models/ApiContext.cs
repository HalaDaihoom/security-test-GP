
using Microsoft.EntityFrameworkCore;
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
}