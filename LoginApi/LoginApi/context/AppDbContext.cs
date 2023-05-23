using LoginApi.Models;
using Microsoft.EntityFrameworkCore;

namespace LoginApi.context
{
    public class AppDbContext : DbContext
    {
                public AppDbContext(DbContextOptions options) : base(options)
            {
            }
            public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
        }

    }
}