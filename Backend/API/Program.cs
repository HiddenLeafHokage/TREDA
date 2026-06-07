using API.Json;
using Application.Interfaces;
using Application.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Persistence.Data;
using Prometheus;
using Serilog;
using Serilog.Formatting.Compact;

// Bootstrap Serilog before the host is built so startup errors are captured
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // ── Serilog ──────────────────────────────────────────────────────────────
    builder.Host.UseSerilog((ctx, services, config) =>
    {
        config.ReadFrom.Configuration(ctx.Configuration)
              .ReadFrom.Services(services)
              .Enrich.FromLogContext();

        if (ctx.HostingEnvironment.IsDevelopment())
            config.WriteTo.Console();
        else
            config.WriteTo.Console(new CompactJsonFormatter()); // structured JSON for Railway log drain
    });

    // ── Sentry ───────────────────────────────────────────────────────────────
    builder.WebHost.UseSentry(o =>
    {
        o.Dsn = builder.Configuration["Sentry:Dsn"] ?? "";
        o.Environment = builder.Environment.EnvironmentName;
        o.TracesSampleRate = builder.Environment.IsDevelopment() ? 1.0 : 0.1;
        o.SendDefaultPii = false;
        o.AttachStacktrace = true;
    });

    // ── Controllers ──────────────────────────────────────────────────────────
    builder.Services.AddControllers().AddJsonOptions(o =>
    {
        o.JsonSerializerOptions.Converters.Add(new ProductConditionJsonConverter());
        o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
    builder.Services.AddEndpointsApiExplorer();

    // ── Swagger (development only) ────────────────────────────────────────────
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo
        {
            Title = "Treda API",
            Version = "v1",
            Description = "API for Treda — Connect Sell Grow.",
            Contact = new OpenApiContact { Name = "Treda Support", Email = "support@treda.com" }
        });
        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Description = "JWT Authorization: Bearer {token}",
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

    // ── Database ─────────────────────────────────────────────────────────────
    // Railway/Render provide DATABASE_URL as postgres:// or postgresql:// URI.
    // Npgsql UseNpgsql() requires key=value format — parse URI manually.
    var rawDatabaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
    var connectionString = !string.IsNullOrWhiteSpace(rawDatabaseUrl)
        ? ParseDatabaseUrl(rawDatabaseUrl)
        : builder.Configuration.GetConnectionString("DefaultConnection")
          ?? throw new InvalidOperationException("No database connection string configured.");

    builder.Services.AddDbContext<TredaDbContext>(options =>
    {
        options.UseNpgsql(connectionString);
        options.ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning));
    });

    // ── Health checks ─────────────────────────────────────────────────────────
    builder.Services.AddHealthChecks()
        .AddDbContextCheck<TredaDbContext>("database");

    // ── Rate limiting ─────────────────────────────────────────────────────────
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

        // Auth endpoints: 10 requests per minute per IP (login, register, OTP)
        options.AddFixedWindowLimiter("auth", o =>
        {
            o.Window = TimeSpan.FromMinutes(1);
            o.PermitLimit = 10;
            o.QueueLimit = 0;
            o.AutoReplenishment = true;
        });

        // Public browsing: 60 requests per minute per IP
        options.AddSlidingWindowLimiter("public", o =>
        {
            o.Window = TimeSpan.FromMinutes(1);
            o.SegmentsPerWindow = 6;
            o.PermitLimit = 60;
            o.QueueLimit = 0;
        });

        // Upload: 20 requests per minute per IP
        options.AddFixedWindowLimiter("uploads", o =>
        {
            o.Window = TimeSpan.FromMinutes(1);
            o.PermitLimit = 20;
            o.QueueLimit = 0;
            o.AutoReplenishment = true;
        });
    });

    // ── HTTP client (used by EmailService to call Brevo REST API) ────────────
    builder.Services.AddHttpClient();

    // ── Application services ─────────────────────────────────────────────────
    builder.Services.AddScoped<ITokenService, TokenService>();
    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<IEmailService, EmailService>();
    builder.Services.AddScoped<IProductService, ProductService>();
    builder.Services.AddScoped<IOrderService, OrderService>();
    builder.Services.AddScoped<IWalletService, WalletService>();
    builder.Services.AddScoped<IMessageService, MessageService>();
    builder.Services.AddScoped<IVendorNotificationService, VendorNotificationService>();
    builder.Services.AddScoped<IVendorTrafficService, VendorTrafficService>();
    builder.Services.AddScoped<IVendorSearchService, VendorSearchService>();

    // ── JWT Authentication ────────────────────────────────────────────────────
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
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

    // ── CORS ──────────────────────────────────────────────────────────────────
    builder.Services.AddCors(options =>
    {
        if (builder.Environment.IsDevelopment())
        {
            options.AddPolicy("CorsPolicy", policy =>
                policy.SetIsOriginAllowed(_ => true)
                      .AllowAnyMethod()
                      .AllowAnyHeader()
                      .AllowCredentials());
        }
        else
        {
            var allowedOrigins = builder.Configuration
                .GetSection("Cors:AllowedOrigins")
                .Get<string[]>() ?? Array.Empty<string>();

            options.AddPolicy("CorsPolicy", policy =>
                policy.WithOrigins(allowedOrigins)
                      .AllowAnyMethod()
                      .AllowAnyHeader()
                      .AllowCredentials());
        }
    });

    // ─────────────────────────────────────────────────────────────────────────
    var app = builder.Build();

    // ── Auto-migrate on startup ───────────────────────────────────────────────
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<TredaDbContext>();
        var startupLogger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        try
        {
            await db.Database.MigrateAsync();
            startupLogger.LogInformation("Database migrations applied successfully.");
        }
        catch (Exception ex)
        {
            startupLogger.LogError(ex, "Failed to apply database migrations.");
            throw;
        }
    }

    // ── HTTP pipeline ─────────────────────────────────────────────────────────
    // Swagger enabled in all environments so frontend/QA can explore the API
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Treda API v1");
        c.RoutePrefix = "swagger";
    });

    app.UseSerilogRequestLogging();
    app.UseCors("CorsPolicy");
    app.UseHttpsRedirection();
    app.UseStaticFiles();

    // Prometheus: expose /metrics (scrape-friendly; protect with firewall or Railway private networking in prod)
    app.UseMetricServer();
    app.UseHttpMetrics();

    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();

    // Health check endpoint
    app.MapHealthChecks("/health", new HealthCheckOptions
    {
        ResponseWriter = async (context, report) =>
        {
            context.Response.ContentType = "application/json";
            var result = System.Text.Json.JsonSerializer.Serialize(new
            {
                status = report.Status.ToString(),
                checks = report.Entries.Select(e => new
                {
                    name = e.Key,
                    status = e.Value.Status.ToString(),
                    description = e.Value.Description
                })
            });
            await context.Response.WriteAsync(result);
        }
    });

    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Application terminated unexpectedly.");
}
finally
{
    Log.CloseAndFlush();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
/// <summary>
/// Converts a postgres:// or postgresql:// URI (provided by Railway/Render)
/// into a Npgsql key=value connection string.
///
/// Parsed manually — intentionally NOT using Uri() because replacing the scheme
/// with http:// causes Uri to default missing ports to 80 instead of 5432.
///
/// Handles both formats Render/Railway provide:
///   postgres://user:pass@host:5432/db       (external URL — has port)
///   postgres://user:pass@host/db            (internal URL — no port, defaults to 5432)
/// </summary>
static string ParseDatabaseUrl(string url)
{
    // Strip scheme
    var withoutScheme = System.Text.RegularExpressions.Regex.Replace(
        url, @"^postgres(?:ql)?://", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // Split credentials from host: user:pass@host:port/db
    var atIndex  = withoutScheme.IndexOf('@');
    var userInfo = withoutScheme[..atIndex].Split(':', 2);
    var username = Uri.UnescapeDataString(userInfo[0]);
    var password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : string.Empty;

    // Split host+port from database path
    var remainder  = withoutScheme[(atIndex + 1)..];
    var slashIndex = remainder.IndexOf('/');
    var hostPart   = slashIndex >= 0 ? remainder[..slashIndex]  : remainder;
    var database   = slashIndex >= 0 ? remainder[(slashIndex + 1)..] : string.Empty;

    // Remove query string from database name if present (e.g. /db?sslmode=require)
    var queryIndex = database.IndexOf('?');
    if (queryIndex >= 0) database = database[..queryIndex];

    // Split host from optional port — default to 5432 if not present
    var colonIndex = hostPart.LastIndexOf(':');
    string host;
    int    port;
    if (colonIndex >= 0 && int.TryParse(hostPart[(colonIndex + 1)..], out var parsedPort))
    {
        host = hostPart[..colonIndex];
        port = parsedPort;
    }
    else
    {
        host = hostPart;
        port = 5432;
    }

    return $"Host={host};Port={port};Database={database};Username={username};Password={password};SSL Mode=Require;Trust Server Certificate=true";
}
