# Treda — Developer Onboarding Guide

> Read this top to bottom before touching any code. It will save you hours.

---

## 1. What is Treda?

Treda is a **marketplace platform** (think Jiji / Jumia-light) built for Nigerian vendors. Vendors register, list products, and receive buyer inquiries. Buyers can browse, chat, and place orders — including as guests without registering.

**This repo** is the backend API only. The frontend is a separate repo deployed on Vercel.

---

## 2. Prerequisites

Install these before anything else:

| Tool | Version | Download |
|------|---------|----------|
| .NET SDK | 9.0+ | https://dotnet.microsoft.com/download/dotnet/9.0 |
| Docker Desktop | Latest | https://www.docker.com/products/docker-desktop |
| Git | Any | https://git-scm.com |
| pgAdmin 4 (optional) | Latest | https://www.pgadmin.org/download |

Verify installs:
```bash
dotnet --version   # should show 9.x.x
docker --version   # should show 24.x or higher
```

---

## 3. First-Time Setup

### Step 1 — Clone the repo

```bash
git clone https://github.com/HiddenLeafHokage/TREDA.git
cd TREDA/Backend
```

### Step 2 — Start the project

```bash
docker compose up --build
```

This starts:
- **PostgreSQL 16** on `localhost:5432`
- **Treda API** on `http://localhost:8080`

The database schema is created automatically on first startup — no manual migration needed.

### Step 3 — Verify it's working

Open your browser:
```
http://localhost:8080/swagger      ← full API documentation
http://localhost:8080/health       ← should show {"status":"Healthy"}
http://localhost:8080/api/categories  ← should return 9 categories
```

If you see all three working — you're done. Start coding.

---

## 4. Project Structure (understand this first)

```
Backend/
├── API/              ← Entry point. Controllers live here. Don't put logic here.
├── Application/      ← ALL business logic lives here. Services + DTOs + Interfaces.
├── Domain/           ← Pure data. Entities and enums only. No dependencies.
└── Persistence/      ← Database only. DbContext and migrations.
```

### The golden rule
**Never skip layers.** Controllers call services. Services call the DB via DbContext. Nothing else.

```
Controller  →  IService  →  DbContext  →  Database
    ↑              ↑
 API layer    Application layer
```

If you find yourself writing database queries in a controller — stop and move it to a service.

---

## 5. How to Add a New Feature

Follow this exact order every time:

### Step 1 — Add the entity (if new data is needed)
In `Domain/Entities/`, create a new class:
```csharp
// Domain/Entities/Review.cs
public class Review
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string ProductId { get; set; } = string.Empty;
    public string ReviewText { get; set; } = string.Empty;
    public int Rating { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
```

### Step 2 — Register it in DbContext
In `Persistence/Data/TredaDbContext.cs`:
```csharp
public DbSet<Review> Reviews { get; set; }
```
Add configuration in `OnModelCreating` if needed (indexes, relationships, precision).

### Step 3 — Create a migration
```bash
cd Backend
dotnet ef migrations add AddReviews --project Persistence --startup-project API
```
Check the generated migration file — make sure it looks right before continuing.

### Step 4 — Create DTOs
In `Application/DTOs/`, create request and response models:
```csharp
// Application/DTOs/Review/CreateReviewDto.cs
public class CreateReviewDto
{
    [Required] public string ProductId { get; set; } = string.Empty;
    [Required][MaxLength(500)] public string ReviewText { get; set; } = string.Empty;
    [Range(1, 5)] public int Rating { get; set; }
}
```

### Step 5 — Create the interface
In `Application/Interfaces/`:
```csharp
// Application/Interfaces/IReviewService.cs
public interface IReviewService
{
    Task<ApiResponse<ReviewResponseDto>> CreateReviewAsync(CreateReviewDto dto, string buyerId);
    Task<ApiResponse<List<ReviewResponseDto>>> GetProductReviewsAsync(string productId);
}
```

### Step 6 — Implement the service
In `Application/Services/`:
```csharp
// Application/Services/ReviewService.cs
public class ReviewService : IReviewService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<ReviewService> _logger;
    // ... implement interface methods
}
```

### Step 7 — Register in DI
In `API/Program.cs`, find the application services section:
```csharp
builder.Services.AddScoped<IReviewService, ReviewService>();
```

### Step 8 — Create the controller
In `API/Controllers/`:
```csharp
[ApiController]
[Route("api/[controller]")]
[SimpleAuthorize] // or [SimpleAuthorize(AppConstants.Roles.Vendor)]
public class ReviewsController : ControllerBase
{
    private readonly IReviewService _reviewService;
    // ... implement endpoints
}
```

### Step 9 — Test it
Restart Docker and open Swagger at `http://localhost:8080/swagger`.

---

## 6. Authentication — How It Works

### JWT token
Every protected endpoint requires:
```
Authorization: Bearer <token>
```

Tokens are issued on login and email verification. They expire after 60 minutes (configurable).

### Getting the current user in a controller
```csharp
private string? VendorId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
private string? UserEmail => User.FindFirst(ClaimTypes.Email)?.Value;
```

### Protecting an endpoint
```csharp
[SimpleAuthorize]                                        // any authenticated user
[SimpleAuthorize(AppConstants.Roles.Vendor)]             // vendors only
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]  // vendor or admin
```

### Public endpoints (no auth)
Don't add `[SimpleAuthorize]`. Routes under `/api/public` are intentionally open.

---

## 7. Standard Response Format

**Always** return `ApiResponse<T>`. Never return raw objects from controllers.

```csharp
// Success
return Ok(ApiResponse<MyDto>.SuccessResult(data, "Fetched successfully."));

// Created
return Ok(ApiResponse<MyDto>.SuccessResult(data, "Created.", ResponseCodes.CREATED));

// Not found
return NotFound(ApiResponse<MyDto>.ErrorResult("Item not found.", ResponseCodes.NOT_FOUND));

// Validation error
return BadRequest(ApiResponse<MyDto>.ErrorResult("Invalid input.", ResponseCodes.VALIDATION_ERROR));

// Unauthorized
return Unauthorized(ApiResponse<MyDto>.ErrorResult("Not allowed.", ResponseCodes.UNAUTHORIZED));
```

Response codes are in `Application/Constants/AppConstants.cs`.

---

## 8. Database — Common Patterns

### Querying
```csharp
// Always scope to the current vendor — never return another vendor's data
var products = await _context.Products
    .Where(p => p.VendorId == vendorId && p.IsActive)
    .OrderByDescending(p => p.CreatedAt)
    .ToListAsync();
```

### Pagination
Use the existing `PagedListDto<T>`:
```csharp
var totalCount = await query.CountAsync();
var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
return PagedListDto<ProductResponseDto>.Create(items, page, pageSize, totalCount);
```

### Never return entities directly
Always map to a DTO before returning from a service. Entities are internal — they contain things like `PasswordHash` that should never leave the API.

---

## 9. Email

The email service uses [Resend](https://resend.com). To test email locally:

1. Add your Resend API key to `docker-compose.yml` under the api service environment:
   ```yaml
   Resend__ApiKey: "re_your_key_here"
   ```
2. Restart: `docker compose up`

Without an API key, emails are **logged to console** only — the OTP code appears in the Docker logs. This is fine for development.

To read logs:
```bash
docker compose logs api --follow
```

Look for lines like:
```
[EMAIL NOT SENT — no API key] To=user@example.com Subject=Verify your Treda account
```

---

## 10. Common Developer Mistakes

| Mistake | Correct approach |
|---------|-----------------|
| Writing DB queries in controllers | Move all DB access to services |
| Returning entities from services | Always map to DTOs |
| Not scoping queries to `vendorId` | Every vendor query must filter by the current vendor's ID |
| Adding new config in code | Put it in `appsettings.json` and read via `IConfiguration` |
| Creating a new service without an interface | Interface first in `Application/Interfaces/`, then implement |
| Throwing generic `Exception` | Throw meaningful exceptions or return `ApiResponse.ErrorResult(...)` |
| Hardcoding strings | Use `AppConstants` for roles, response codes, and limits |

---

## 11. Branching & Git Workflow

```
main          ← production. Every push auto-deploys to Render. Be careful.
feature/*     ← new features (e.g. feature/buyer-reviews)
fix/*         ← bug fixes (e.g. fix/order-status-update)
```

**Never push directly to `main` for new features.** Create a branch, then open a PR.

```bash
git checkout -b feature/your-feature-name
# ... make changes ...
git add .
git commit -m "Add vendor review system"
git push origin feature/your-feature-name
# Open PR on GitHub → get reviewed → merge to main
```

---

## 12. Environment Setup for Local Development

Your `docker-compose.yml` already has all local credentials. You only need to create an `appsettings.Development.json` file if you want to override something locally (this file is gitignored):

```json
{
  "Resend": {
    "ApiKey": "re_your_personal_test_key"
  }
}
```

**Never commit real API keys or secrets.** The `.gitignore` excludes `appsettings.Development.json` and `appsettings.Production.json` for this reason.

---

## 13. Useful Commands

```bash
# Start everything
docker compose up

# Start in background
docker compose up -d

# View live API logs
docker compose logs api --follow

# Rebuild after code changes (if hot reload isn't catching it)
docker compose up --build

# Open a postgres shell
docker exec -it backend-db-1 psql -U treda -d TredaDB

# Add a new EF migration
dotnet ef migrations add MigrationName --project Persistence --startup-project API

# Build without running (check for errors)
cd Backend && dotnet build

# Restore packages
cd Backend && dotnet restore
```

---

## 14. Getting Help

1. **Check the logs first:** `docker compose logs api --follow`
2. **Check the health endpoint:** `http://localhost:8080/health`
3. **Check Swagger for endpoint details:** `http://localhost:8080/swagger`
4. **Ask the team** — don't spend more than 30 minutes stuck before asking

---

## 15. Key Files to Know

| File | What it does |
|------|-------------|
| `API/Program.cs` | App bootstrap — DI, middleware, CORS, JWT, rate limiting |
| `Persistence/Data/TredaDbContext.cs` | Database schema — all table configs and relationships |
| `Application/Constants/AppConstants.cs` | Roles, response codes, file size limits |
| `Application/DTOs/Common/ApiResponse.cs` | Standard response wrapper — use this everywhere |
| `API/Attributes/SimpleAuthorizeAttribute.cs` | JWT validation and role checking for protected endpoints |
| `docker-compose.yml` | Local dev environment — API + PostgreSQL |
| `Dockerfile` | Production container build |
