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
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.ResponseCompression;
using Npgsql;
using System.IO.Compression;
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

        // WriteTo.Async keeps console I/O off the request thread (Serilog.Sinks.Async).
        if (ctx.HostingEnvironment.IsDevelopment())
            config.WriteTo.Async(a => a.Console());
        else
            config.WriteTo.Async(a => a.Console(new CompactJsonFormatter())); // structured JSON for log drains
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

    // Tune the Npgsql connection pool. Defaults (MaxPoolSize=100) can exhaust Neon's free-tier
    // connection ceiling, and Neon scales to zero when idle — which silently kills pooled
    // connections. A short idle lifetime prunes them before they go stale.
    connectionString = new NpgsqlConnectionStringBuilder(connectionString)
    {
        MaxPoolSize = 20,
        MinPoolSize = 0,
        ConnectionIdleLifetime = 60, // seconds — drop idle connections before Neon suspends
        Timeout = 15,                // connect timeout (Neon cold start)
        CommandTimeout = 30
    }.ConnectionString;

    // DbContext pooling reuses context instances instead of allocating one per request.
    builder.Services.AddDbContextPool<TredaDbContext>(options =>
    {
        options.UseNpgsql(connectionString);
        options.ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning));
    });

    // ── Health checks ─────────────────────────────────────────────────────────
    builder.Services.AddHealthChecks()
        .AddDbContextCheck<TredaDbContext>("database");

    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                                   ForwardedHeaders.XForwardedProto |
                                   ForwardedHeaders.XForwardedHost;
        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();
    });

    // ── Rate limiting ─────────────────────────────────────────────────────────
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

        // Partition every policy by client IP so one caller can't exhaust the limit for
        // everyone. RemoteIpAddress is the real client IP because UseForwardedHeaders runs
        // earlier in the pipeline (Render terminates TLS at its proxy).
        static string ClientKey(HttpContext http) =>
            http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Auth endpoints: 10 requests per minute per IP (login, register, OTP)
        options.AddPolicy("auth", http => RateLimitPartition.GetFixedWindowLimiter(
            ClientKey(http), _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(1),
                PermitLimit = 10,
                QueueLimit = 0,
                AutoReplenishment = true
            }));

        // Public browsing: 60 requests per minute per IP
        options.AddPolicy("public", http => RateLimitPartition.GetSlidingWindowLimiter(
            ClientKey(http), _ => new SlidingWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6,
                PermitLimit = 60,
                QueueLimit = 0
            }));

        // Upload: 20 requests per minute per IP
        options.AddPolicy("uploads", http => RateLimitPartition.GetFixedWindowLimiter(
            ClientKey(http), _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(1),
                PermitLimit = 20,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    });

    // ── Response compression ─────────────────────────────────────────────────
    // JSON payloads (product/vendor lists) shrink ~70-80%. EnableForHttps is required because
    // ASP.NET disables compression over TLS by default.
    builder.Services.AddResponseCompression(options =>
    {
        options.EnableForHttps = true;
        options.Providers.Add<BrotliCompressionProvider>();
        options.Providers.Add<GzipCompressionProvider>();
    });
    builder.Services.Configure<BrotliCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);
    builder.Services.Configure<GzipCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);

    // ── In-memory cache (categories; per-instance — swap for Redis if you scale out) ──────────
    builder.Services.AddMemoryCache();

    // ── HTTP client (used by EmailService to call Brevo REST API) ────────────
    builder.Services.AddHttpClient();
    builder.Services.AddHttpContextAccessor();

    // ── File storage (logos, covers, product images) ─────────────────────────
    // Swappable seam: Cloudinary in production (permanent CDN URLs that survive
    // Render redeploys), local disk only as a dev fallback when Cloudinary keys
    // are absent. To move to AWS S3 later, add an S3FileStorageService and swap
    // this single registration — no controller or service changes required.
    var cloudinaryConfigured = !string.IsNullOrWhiteSpace(builder.Configuration["Cloudinary:CloudName"]) &&
                               !string.IsNullOrWhiteSpace(builder.Configuration["Cloudinary:ApiKey"]) &&
                               !string.IsNullOrWhiteSpace(builder.Configuration["Cloudinary:ApiSecret"]);
    if (cloudinaryConfigured)
    {
        builder.Services.AddScoped<IFileStorageService, CloudinaryFileStorageService>();
    }
    else
    {
        Log.Warning("Cloudinary not configured — uploads use LOCAL DISK and will be lost on redeploy. " +
                    "Set Cloudinary__CloudName, Cloudinary__ApiKey and Cloudinary__ApiSecret in production.");
        builder.Services.AddScoped<IFileStorageService, API.Services.LocalDiskFileStorageService>();
    }

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
    builder.Services.AddScoped<ISubscriptionService, SubscriptionService>();

    // ── JWT Authentication ────────────────────────────────────────────────────
    var jwtSecret = builder.Configuration["Jwt:Secret"];
    if (string.IsNullOrWhiteSpace(jwtSecret))
        throw new InvalidOperationException(
            "JWT Secret is not configured. Set the Jwt__Secret environment variable (it is intentionally empty in appsettings.json so secrets never live in source control).");
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
    // Compression must run before anything writes a response body.
    app.UseResponseCompression();

    // Swagger enabled in all environments so frontend/QA can explore the API
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Treda API v1");
        c.RoutePrefix = "swagger";
    });

    app.UseForwardedHeaders();
    app.UseSerilogRequestLogging();
    app.UseCors("CorsPolicy");
    app.UseHttpsRedirection();
    app.UseStaticFiles();

    // Prometheus: expose /metrics (scrape-friendly; protect with firewall or Railway private networking in prod)
    app.UseMetricServer();
    app.UseHttpMetrics();

    // Enabled by default; integration tests set RateLimiting:Enabled=false so the shared
    // test server doesn't exhaust the auth window across many register/login calls.
    if (app.Configuration.GetValue("RateLimiting:Enabled", true))
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
// Let WebApplicationFactory's host-capture signal (StopTheHostException, thrown during
// integration tests) and HostAbortedException propagate instead of being swallowed here.
catch (Exception ex) when (ex is not HostAbortedException &&
                           ex.GetType().Name is not "StopTheHostException")
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

// Exposed so the integration-test project can boot the real app via WebApplicationFactory<Program>.
public partial class Program { }
