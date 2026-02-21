// API/Program.cs
using Application.Interfaces;
using Application.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IO;
using Persistence.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure SQL Server (Local - Fast & Free for Development)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Server=(localdb)\\mssqllocaldb;Database=TredaDB;Trusted_Connection=true;TrustServerCertificate=true;";

builder.Services.AddDbContext<TredaDbContext>(options =>
{
    options.UseSqlServer(connectionString);
    // Allow migrations to run even when EF detects minor model/snapshot drift (e.g. value comparer)
    options.ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning));
});

// Register services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<IProductService, ProductService>();
builder.Services.AddScoped<IOrderService, OrderService>();
builder.Services.AddScoped<IWalletService, WalletService>();
builder.Services.AddScoped<IMessageService, MessageService>();

// Configure Swagger (all endpoints visible for testing and frontend integration)
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { 
        Title = "Treda API", 
        Version = "v1",
        Description = "API for Treda - Connect Sell Grow. Use **Authorize** with Bearer token (from login/register) to test protected endpoints.",
        Contact = new OpenApiContact
        {
            Name = "Treda Support",
            Email = "support@treda.com"
        }
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization: Bearer {token}. Get token from POST /api/auth/login or register-vendor.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});




// Add logging
builder.Services.AddLogging();

// Configure JWT Authentication
var jwtSecret = builder.Configuration["Jwt:Secret"] 
    ?? throw new InvalidOperationException("JWT Secret is not configured");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "treda-api";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "treda-client";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes(jwtSecret)),
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = true,
        ValidAudience = jwtAudience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

// CORS - Allow all for development (easy testing)
builder.Services.AddCors(options => 
    options.AddPolicy("AllowAll", policy => 
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));


var app = builder.Build();

// One-time schema fix: if Products still has SellerId (old schema), run the migration script so VendorId exists
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<TredaDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    var scriptPath = Path.Combine(app.Environment.ContentRootPath, "..", "Persistence", "Scripts", "ApplyProductCategoriesAndVendorId.sql");
    if (File.Exists(scriptPath))
    {
        try
        {
            var sql = await File.ReadAllTextAsync(scriptPath);
            // Split on GO so batch 2 (which uses VendorId) is compiled after batch 1 adds the column
            var batches = System.Text.RegularExpressions.Regex.Split(sql, @"^\s*GO\s*$", System.Text.RegularExpressions.RegexOptions.Multiline | System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                .Select(b => b.Trim())
                .Where(b => b.Length > 0)
                .ToList();
            var conn = db.Database.GetDbConnection();
            await conn.OpenAsync();
            foreach (var batch in batches)
            {
                if (string.IsNullOrWhiteSpace(batch)) continue;
                await using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = batch;
                    await cmd.ExecuteNonQueryAsync();
                }
            }
            logger.LogInformation("Applied ProductCategoriesAndVendorId schema fix. VendorId column and categories are now in place.");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to apply schema fix. If you see 'Invalid column name VendorId', run ApplyProductCategoriesAndVendorId.sql against (localdb)\\mssqllocaldb, database TredaDB.");
        }
    }
}

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

}

app.UseHttpsRedirection();
app.UseStaticFiles(); // serve wwwroot (e.g. /uploads/xxx for uploaded files)
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();