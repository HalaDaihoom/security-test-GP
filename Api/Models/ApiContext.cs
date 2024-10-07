using Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Api.Models;

public class ApiContext : DbContext
{
    public ApiContext() { }

    public ApiContext(DbContextOptions<ApiContext> options)
        : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
    
    // protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    // {
    //     optionsBuilder.UseMySQL("Server=localhost;Database=Api;User=root;Password=12345678;");

    //     base.OnConfiguring(optionsBuilder);
    // }

    public DbSet<User> User {get ; set;}
   
}