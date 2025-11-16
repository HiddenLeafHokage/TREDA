// Persistence/Data/TredaDbContext.cs
using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Persistence.Data;

public class TredaDbContext : DbContext
{
    public TredaDbContext(DbContextOptions<TredaDbContext> options) : base(options) { }
    
    public DbSet<User> Users { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
    public DbSet<EmailVerificationToken> EmailVerificationTokens { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);
            entity.HasIndex(u => u.Email).IsUnique();
            entity.HasIndex(u => u.GoogleId).IsUnique();
            entity.Property(u => u.UserType).HasConversion<string>();
            entity.Property(u => u.UserType).HasConversion<string>();
            entity.Property(u => u.DeliveryMethod).HasConversion<string>();

             entity.HasMany(u => u.PasswordResetTokens)
                  .WithOne(prt => prt.User)
                  .HasForeignKey(prt => prt.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
                  
            entity.HasMany(u => u.EmailVerificationTokens)
                  .WithOne(evt => evt.User)
                  .HasForeignKey(evt => evt.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });



        // Product configuration
        modelBuilder.Entity<Product>(entity =>
        {
            entity.HasKey(p => p.Id);
            entity.HasOne(p => p.Seller)
                  .WithMany()
                  .HasForeignKey(p => p.SellerId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
        // PasswordResetToken configuration
        modelBuilder.Entity<PasswordResetToken>(entity =>
        {
            entity.HasKey(prt => prt.Id);
            entity.HasIndex(prt => prt.Token);
            entity.HasIndex(prt => prt.UserId);
        });
        
        // EmailVerificationToken configuration
        modelBuilder.Entity<EmailVerificationToken>(entity =>
        {
            entity.HasKey(evt => evt.Id);
            entity.HasIndex(evt => evt.Token);
            entity.HasIndex(evt => evt.UserId);
        });
    }
}