// Persistence/Data/TredaDbContext.cs
using System.Text.Json;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Persistence.Data;

public class TredaDbContext : DbContext
{
    private static readonly ValueConverter<List<string>, string> ImageUrlsConverter = new(
        v => ListStringJson.Serialize(v),
        v => ListStringJson.Deserialize(v));

    /// <summary>Reads "Seller" or "Vendor" from DB as Vendor; always writes "Vendor".</summary>
    private static readonly ValueConverter<UserType, string> UserTypeConverter = new(
        v => v.ToString(),
        v => string.Equals(v, "Seller", StringComparison.OrdinalIgnoreCase) ? UserType.Vendor : Enum.Parse<UserType>(v));
    public TredaDbContext(DbContextOptions<TredaDbContext> options) : base(options) { }
    
    public DbSet<User> Users { get; set; }
    public DbSet<ProductCategory> ProductCategories { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<VendorWallet> VendorWallets { get; set; }
    public DbSet<WalletTransaction> WalletTransactions { get; set; }
    public DbSet<Conversation> Conversations { get; set; }
    public DbSet<Message> Messages { get; set; }
    public DbSet<ProductPromotion> ProductPromotions { get; set; }
    public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
    public DbSet<EmailVerificationToken> EmailVerificationTokens { get; set; }
    public DbSet<VendorNotification> VendorNotifications { get; set; }
    public DbSet<VendorTrafficEvent> VendorTrafficEvents { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("Users");
            entity.HasKey(u => u.Id);
            entity.HasIndex(u => u.Email).IsUnique();
            entity.HasIndex(u => u.GoogleId).IsUnique();
            entity.HasIndex(u => u.PhoneNumber).IsUnique().HasFilter("[PhoneNumber] IS NOT NULL");
            entity.Property(u => u.UserType).HasConversion(UserTypeConverter);
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

        // ProductCategory configuration and seed (Jiji-style categories)
        modelBuilder.Entity<ProductCategory>(entity =>
        {
            entity.ToTable("ProductCategories");
            entity.HasKey(c => c.Id);
            entity.HasIndex(c => c.Slug).IsUnique();
            entity.HasData(
                new ProductCategory { Id = "cat-phones", Name = "Phones & Tablets", Slug = "phones-tablets", Description = "Mobile phones and tablets", DisplayOrder = 1, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-electronics", Name = "Electronics", Slug = "electronics", Description = "Electronics and gadgets", DisplayOrder = 2, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-fashion", Name = "Fashion", Slug = "fashion", Description = "Clothing and accessories", DisplayOrder = 3, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-food", Name = "Food & Beverage", Slug = "food-beverage", Description = "Food items and drinks", DisplayOrder = 4, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-accessories", Name = "Accessories", Slug = "accessories", Description = "Accessories and more", DisplayOrder = 5, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-home", Name = "Home & Garden", Slug = "home-garden", Description = "Home and garden items", DisplayOrder = 6, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-vehicles", Name = "Vehicles", Slug = "vehicles", Description = "Cars, bikes and parts", DisplayOrder = 7, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-health", Name = "Health & Beauty", Slug = "health-beauty", Description = "Health and beauty products", DisplayOrder = 8, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) },
                new ProductCategory { Id = "cat-other", Name = "Other", Slug = "other", Description = "Other items", DisplayOrder = 99, CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) }
            );
        });

        // Product configuration
        modelBuilder.Entity<Product>(entity =>
        {
            entity.ToTable("Products");
            entity.HasKey(p => p.Id);
            entity.Property(p => p.Price).HasPrecision(18, 2);
            entity.Property(p => p.ImageUrls)
                .HasConversion(ImageUrlsConverter)
                .Metadata.SetValueComparer(new ValueComparer<List<string>>(
                    (c1, c2) => (c1 == null && c2 == null) || (c1 != null && c2 != null && c1.SequenceEqual(c2)),
                    c => c == null ? 0 : c.Aggregate(0, (a, v) => HashCode.Combine(a, v == null ? 0 : v.GetHashCode())),
                    c => c == null ? new List<string>() : c.ToList()));
            entity.Property(p => p.Condition).HasConversion<string>();
            entity.HasOne(p => p.Category)
                  .WithMany()
                  .HasForeignKey(p => p.CategoryId)
                  .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(p => p.Vendor)
                  .WithMany()
                  .HasForeignKey(p => p.VendorId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
        
        // PasswordResetToken configuration
        modelBuilder.Entity<PasswordResetToken>(entity =>
        {
            entity.ToTable("PasswordResetTokens");
            entity.HasKey(prt => prt.Id);
            entity.HasIndex(prt => prt.Token);
            entity.HasIndex(prt => prt.UserId);
        });
        
        // EmailVerificationToken configuration
        modelBuilder.Entity<EmailVerificationToken>(entity =>
        {
            entity.ToTable("EmailVerificationTokens");
            entity.HasKey(evt => evt.Id);
            entity.HasIndex(evt => evt.Token);
            entity.HasIndex(evt => evt.UserId);
        });

        // Order configuration
        modelBuilder.Entity<Order>(entity =>
        {
            entity.ToTable("Orders");
            entity.HasKey(o => o.Id);
            entity.Property(o => o.Amount).HasPrecision(18, 2);
            entity.Property(o => o.Status).HasConversion<string>();
            entity.HasIndex(o => o.VendorId);
            entity.HasIndex(o => o.BuyerId).HasFilter("[BuyerId] IS NOT NULL");
            entity.HasOne(o => o.Vendor).WithMany().HasForeignKey(o => o.VendorId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(o => o.Buyer).WithMany().HasForeignKey(o => o.BuyerId).OnDelete(DeleteBehavior.SetNull).IsRequired(false);
            entity.HasOne(o => o.Product).WithMany().HasForeignKey(o => o.ProductId).OnDelete(DeleteBehavior.SetNull);
        });

        // VendorWallet configuration
        modelBuilder.Entity<VendorWallet>(entity =>
        {
            entity.ToTable("VendorWallets");
            entity.HasKey(w => w.Id);
            entity.Property(w => w.Balance).HasPrecision(18, 2);
            entity.HasIndex(w => w.VendorId).IsUnique();
            entity.HasOne(w => w.Vendor).WithMany().HasForeignKey(w => w.VendorId).OnDelete(DeleteBehavior.Cascade);
        });

        // WalletTransaction configuration
        modelBuilder.Entity<WalletTransaction>(entity =>
        {
            entity.ToTable("WalletTransactions");
            entity.HasKey(t => t.Id);
            entity.Property(t => t.Amount).HasPrecision(18, 2);
            entity.Property(t => t.Type).HasConversion<string>();
            entity.HasIndex(t => t.VendorId);
        });

        // Conversation configuration
        modelBuilder.Entity<Conversation>(entity =>
        {
            entity.ToTable("Conversations");
            entity.HasIndex(c => c.VendorId);
            entity.HasIndex(c => c.BuyerId).HasFilter("[BuyerId] IS NOT NULL");
            entity.HasOne(c => c.Vendor).WithMany().HasForeignKey(c => c.VendorId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(c => c.Buyer).WithMany().HasForeignKey(c => c.BuyerId).OnDelete(DeleteBehavior.SetNull).IsRequired(false);
            entity.HasOne(c => c.Product).WithMany().HasForeignKey(c => c.ProductId).OnDelete(DeleteBehavior.SetNull);
            entity.HasMany(c => c.Messages).WithOne(m => m.Conversation).HasForeignKey(m => m.ConversationId).OnDelete(DeleteBehavior.Cascade);
        });

        // Message configuration
        modelBuilder.Entity<Message>(entity =>
        {
            entity.ToTable("Messages");
            entity.HasKey(m => m.Id);
            entity.HasIndex(m => m.ConversationId);
            entity.HasOne(m => m.Sender).WithMany().HasForeignKey(m => m.SenderId).OnDelete(DeleteBehavior.SetNull).IsRequired(false);
        });

        // ProductPromotion configuration
        modelBuilder.Entity<ProductPromotion>(entity =>
        {
            entity.ToTable("ProductPromotions");
            entity.HasKey(p => p.Id);
            entity.Property(p => p.AmountPaid).HasPrecision(18, 2);
            entity.HasIndex(p => p.ProductId);
            entity.HasOne(p => p.Product).WithMany().HasForeignKey(p => p.ProductId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VendorNotification>(entity =>
        {
            entity.ToTable("VendorNotifications");
            entity.HasKey(n => n.Id);
            entity.Property(n => n.Category).HasConversion<string>().HasMaxLength(32);
            entity.Property(n => n.ActionKind).HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(n => new { n.VendorId, n.IsRead });
            entity.HasIndex(n => new { n.VendorId, n.Category });
            entity.HasIndex(n => n.CreatedAt);
            entity.HasOne(n => n.Vendor).WithMany().HasForeignKey(n => n.VendorId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VendorTrafficEvent>(entity =>
        {
            entity.ToTable("VendorTrafficEvents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.EventType).HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(e => new { e.VendorId, e.EventType, e.CreatedAt });
            entity.HasIndex(e => e.CreatedAt);
        });
    }
}

internal static class ListStringJson
{
    public static string Serialize(List<string> v) => JsonSerializer.Serialize(v);
    public static List<string> Deserialize(string v) =>
        string.IsNullOrEmpty(v) ? new List<string>() : JsonSerializer.Deserialize<List<string>>(v)!;
}