using Microsoft.AspNetCore.Mvc.Testing;

namespace Treda.IntegrationTests;

/// <summary>
/// Boots the real Treda API (via <c>Program</c>) against a real PostgreSQL database, so tests
/// exercise the actual middleware, EF Core, and SQL — not mocks.
///
/// Connection comes from the TEST_DB_CONNECTION env var, falling back to the local Docker
/// Postgres (a separate <c>treda_test</c> database so it never touches your dev data).
/// EF's startup migration creates that database + schema and seeds it automatically.
///
/// Config is injected via real environment variables, NOT ConfigureAppConfiguration: Program.cs
/// reads JWT + connection settings from builder.Configuration BEFORE builder.Build(), and the
/// factory's config hooks only apply during Build — too late. Environment variables are read by
/// WebApplication.CreateBuilder up front, so they take effect.
///
/// Cloudinary/Brevo are left unconfigured, so uploads use the local-disk fallback and emails are
/// logged instead of sent — which is exactly what tests want.
/// </summary>
public class TredaApiFactory : WebApplicationFactory<Program>
{
    private readonly string _connectionString =
        Environment.GetEnvironmentVariable("TEST_DB_CONNECTION")
        ?? "Host=localhost;Port=5432;Database=treda_test;Username=treda;Password=treda_dev_pass";

    public TredaApiFactory()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        // Ensure a stray DATABASE_URL (e.g. for Render) can't override the test connection.
        Environment.SetEnvironmentVariable("DATABASE_URL", null);
        Environment.SetEnvironmentVariable("ConnectionStrings__DefaultConnection", _connectionString);
        Environment.SetEnvironmentVariable("Jwt__Secret", "integration-test-jwt-secret-at-least-32-characters-long");
        Environment.SetEnvironmentVariable("Jwt__Issuer", "treda-api");
        Environment.SetEnvironmentVariable("Jwt__Audience", "treda-client");
        // Disable rate limiting: the shared test server would otherwise hit the auth window.
        Environment.SetEnvironmentVariable("RateLimiting__Enabled", "false");
        Environment.SetEnvironmentVariable("Admin__ApiKey", "test-admin-key");
    }
}
