# Treda API

> **Connect. Sell. Grow.** — Backend API for the Treda marketplace platform.

A .NET 9 REST API powering a Jiji-style classifieds marketplace. Vendors list products, buyers browse and contact sellers, orders are tracked, and payments flow through a vendor wallet.

**Production URL:** `https://treda-mjiy.onrender.com`  
**Health check:** `https://treda-mjiy.onrender.com/health`  
**Swagger (local dev only):** `http://localhost:8080/swagger`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | .NET 9 / ASP.NET Core |
| Database | PostgreSQL 16 (via Npgsql + EF Core 9) |
| Authentication | JWT (HS256) + BCrypt password hashing |
| Email | Resend REST API |
| Logging | Serilog — plain console in dev, compact JSON in production |
| Error tracking | Sentry |
| Metrics | Prometheus (`/metrics`) |
| Container | Docker + Docker Compose |

---

## Architecture

Clean Architecture — 4 projects:

```
Treda.sln
├── API/              → Controllers, middleware, Program.cs (entry point)
├── Application/      → Business logic, services, interfaces, DTOs
├── Domain/           → Entities and enums (no dependencies)
└── Persistence/      → EF Core DbContext, migrations
```

**Dependency rule:** Domain ← Persistence ← Application ← API. Inner layers never reference outer layers.

---

## Running Locally

### Option A — Docker Compose (recommended, zero setup)

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/).

```bash
cd Backend
docker compose up --build
```

- API: `http://localhost:8080`
- Swagger: `http://localhost:8080/swagger`
- PostgreSQL: `localhost:5432`

Stop: `docker compose down`  
Stop and wipe DB: `docker compose down -v`

### Option B — dotnet run (faster for active development)

Requires [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) and a running PostgreSQL instance.

Start just the database:
```bash
docker run -d --name treda-db \
  -e POSTGRES_DB=TredaDB \
  -e POSTGRES_USER=treda \
  -e POSTGRES_PASSWORD=treda_dev_pass \
  -p 5432:5432 \
  postgres:16-alpine
```

Run the API:
```bash
cd Backend/API
dotnet run
```

- API: `https://localhost:5001`
- Swagger: `https://localhost:5001/swagger`

---

## Environment Variables

### Local — `docker-compose.yml` already sets these defaults

| Variable | Description |
|----------|-------------|
| `ConnectionStrings__DefaultConnection` | PostgreSQL connection string |
| `Jwt__Secret` | Signing secret — min 32 chars |
| `Jwt__Issuer` | Token issuer (`treda-api`) |
| `Jwt__Audience` | Token audience (`treda-client`) |
| `Jwt__ExpirationMinutes` | Token lifetime in minutes (default `60`) |

### Production — set on Render/Railway dashboard

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Auto-injected by Render PostgreSQL plugin |
| `ASPNETCORE_ENVIRONMENT` | Must be `Production` |
| `Jwt__Secret` | Strong random secret — generate at [randomkeygen.com](https://randomkeygen.com) |
| `Cors__AllowedOrigins__0` | Frontend domain e.g. `https://app-treda.vercel.app` |
| `Cors__AllowedOrigins__1` | Optional extra origin e.g. `http://localhost:3000` |
| `Resend__ApiKey` | API key from [resend.com](https://resend.com) |
| `Resend__FromAddress` | e.g. `Treda <noreply@yourdomain.com>` |
| `Sentry__Dsn` | DSN from [sentry.io](https://sentry.io) (optional) |

> `DATABASE_URL` is automatically parsed from `postgres://` URI format to the Npgsql key=value format on startup — no manual conversion needed.

---

## API Reference

All responses use this envelope:
```json
{
  "success": true,
  "message": "...",
  "code": 0,
  "data": {},
  "timestamp": "2026-06-04T10:00:00Z"
}
```

### Auth — `/api/auth` — Rate limited: 10 req/min
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/register-vendor` | None | Register vendor, sends OTP email |
| `POST` | `/verify-email` | None | Verify email with OTP |
| `POST` | `/resend-verification` | None | Resend OTP email |
| `POST` | `/login` | None | Login — returns JWT + refresh token |
| `POST` | `/refresh-token` | None | Exchange refresh token for new JWT |
| `POST` | `/forgot-password` | None | Send password reset OTP |
| `POST` | `/reset-password` | None | Reset password using OTP |
| `GET`  | `/me` | Bearer | Get current user profile |

### Products — `/api/products`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`    | `/` | Vendor | My products (paginated) |
| `GET`    | `/all` | Vendor | All my products (no pagination) |
| `GET`    | `/{id}` | Vendor | Single product |
| `POST`   | `/` | Vendor | Create product |
| `PUT`    | `/{id}` | Vendor | Update product |
| `DELETE` | `/{id}` | Vendor | Delete product |
| `PATCH`  | `/{id}/toggle-active` | Vendor | Toggle active/inactive |

### Public Browsing — `/api/public` — Rate limited: 60 req/min
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/products` | None | Browse all active products |
| `GET`  | `/products/{id}` | None | View single product |
| `GET`  | `/vendors/{vendorId}/products` | None | Browse a vendor's products |
| `POST` | `/conversations` | None | Start a conversation (guest or registered) |
| `POST` | `/conversations/{id}/messages` | None | Send a message |
| `GET`  | `/conversations/{id}/messages` | None | Get messages in a conversation |
| `POST` | `/orders` | None | Create order/inquiry as guest |

### Orders — `/api/orders`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/` | Vendor | My orders (paginated, filterable by date/status) |
| `GET`  | `/{id}` | Vendor | Single order |
| `PUT`  | `/{id}/status` | Vendor | Update order status |
| `PUT`  | `/{id}/amount` | Vendor | Update invoice amount |

### Vendor Dashboard — `/api/vendor`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/dashboard` | Vendor | Stats: total sales, orders today, wallet balance |
| `GET`  | `/profile` | Vendor | Get vendor profile |
| `PUT`  | `/profile` | Vendor | Update vendor profile |

### Wallet — `/api/wallet`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/` | Vendor | Wallet balance |
| `GET`  | `/transactions` | Vendor | Transaction history |
| `POST` | `/promote` | Vendor | Promote a product (Treda Ads) |

### Messages — `/api/messages`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/conversations` | Vendor | All conversations |
| `GET`  | `/conversations/{id}` | Vendor | Conversation + messages |
| `POST` | `/conversations/{id}/messages` | Vendor | Send a message |

### Categories — `/api/categories`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/` | None | All product categories |

### File Upload — `/api/upload` — Rate limited: 20 req/min
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/` | Vendor | Upload image or PDF (max 5 MB, returns URL) |

### Notifications — `/api/vendor-notifications`
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/` | Vendor | Get notifications |
| `PATCH` | `/{id}/read` | Vendor | Mark notification as read |

### System
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/health` | None | Health check — returns DB status |
| `GET`  | `/metrics` | None | Prometheus scrape endpoint |
| `GET`  | `/api/auth/test` | None | Smoke test |

---

## Authentication

```
1. POST /api/auth/register-vendor  → account created, OTP sent to email
2. POST /api/auth/verify-email     → email verified, JWT returned
3. All protected requests          → Authorization: Bearer <token>
4. Token expired?                  → POST /api/auth/refresh-token
```

**Token lifetime:** 60 minutes (configurable via `Jwt__ExpirationMinutes`)  
**Refresh token lifetime:** 7 days

---

## Database

Migrations run **automatically on startup** — no manual step needed on deploy.

To add a new migration:
```bash
cd Backend
dotnet ef migrations add <MigrationName> --project Persistence --startup-project API
```

### Viewing data locally
- **pgAdmin 4:** host `localhost`, port `5432`, DB `TredaDB`, user `treda`, password `treda_dev_pass`
- **DBeaver:** same credentials
- **Terminal:** `docker exec -it backend-db-1 psql -U treda -d TredaDB`

### Seeded categories (auto-seeded on first migration)
`cat-phones` · `cat-electronics` · `cat-fashion` · `cat-food` · `cat-accessories` · `cat-home` · `cat-vehicles` · `cat-health` · `cat-other`

---

## Rate Limiting

| Policy | Applied to | Limit |
|--------|-----------|-------|
| `auth` | `/api/auth/*` | 10 req/min per IP |
| `public` | `/api/public/*` | 60 req/min per IP |
| `uploads` | `POST /api/upload` | 20 req/min per IP |

Returns `HTTP 429` when exceeded.

---

## Deployment

### Render (current hosting)
1. Push to `main` — auto-deploys
2. Root directory: `Backend`
3. Runtime: Docker (Dockerfile detected automatically)
4. Add PostgreSQL plugin — `DATABASE_URL` injected automatically
5. Set all production env vars (see table above)

### Moving to Railway
Same steps — same Dockerfile, same env vars. Railway is cheaper at scale ($5/month vs $14/month on Render paid tier).

---

## Project Structure

```
Backend/
├── API/
│   ├── Controllers/         11 controllers
│   ├── Attributes/          SimpleAuthorizeAttribute (JWT + role check)
│   ├── Json/                Custom JSON converters
│   ├── wwwroot/uploads/     User-uploaded files (gitignored, volume-mounted)
│   └── Program.cs           Bootstrap, DI registration, middleware pipeline
├── Application/
│   ├── DTOs/                Request and response models
│   ├── Interfaces/          Service contracts (IAuthService, IEmailService, etc.)
│   ├── Services/            11 service implementations
│   └── Constants/           AppConstants, ResponseCodes, Roles
├── Domain/
│   ├── Entities/            13 EF Core entities
│   └── Enums/               UserType, OrderStatus, ProductCondition, etc.
├── Persistence/
│   ├── Data/                TredaDbContext
│   └── Migrations/          EF Core migration history
├── Dockerfile               Multi-stage build (SDK → ASP.NET runtime)
└── docker-compose.yml       Local dev: API + PostgreSQL 16
```
