# Treda Backend – What’s Remaining, Security, and Improvements

Senior-dev view of where the app stands and what to do next.

---

## 1. What’s remaining (gaps)

| Area | Status | Notes |
|------|--------|--------|
| **Notifications** | Not built | Dashboard “Notifications” screen (All / Orders / Payments / Messages, “Mark all read”, “View Order” / “View Wallet”) has no API. Need a `Notification` entity, create records when orders are created / payments happen, and endpoints: list (with filters), mark read, summary counts. |
| **Email sending** | Stub only | `EmailService` only logs verification and password-reset codes to the console. For production you need a real provider (SendGrid, AWS SES, etc.) and to send actual emails/SMS. |
| **Analytics (extra metrics)** | Stubbed | `Favourites`, `ClickThrough`, `Views`, `TotalSearches` are hard-coded to 0. To show real data you need tracking (e.g. product views, favourites table, search log) and to feed that into the analytics API. |
| **Google login** | Not implemented | Returns 501. Add Google OAuth and map external identity to your `User`. |
| **Buyer registration (optional)** | Exists but not in public flow | You have `POST /api/auth/register` and Buyer role. The product manager wanted “buyer doesn’t register”; if you later want optional buyer accounts, the backend can support it. |
| **Database migrations** | Manual scripts used | You have SQL scripts for schema fixes. For a clean history, consider applying migrations via `dotnet ef database update` and keeping scripts only for one-off data fixes. |

---

## 2. Is it secure?

**What’s in good shape**

- **Auth:** JWT with signing, issuer, audience, expiry; no raw secrets in code (from config).
- **Passwords:** Hashed with BCrypt (no plaintext storage).
- **Queries:** EF Core only (parameterized), no raw SQL concatenation → SQL injection risk is low.
- **Uploads:** Extension allowlist (e.g. .jpg, .png, .pdf), max size (e.g. 5 MB), and new GUID filenames (no path traversal from client).
- **Vendor scoping:** Vendor endpoints use `VendorId` from the token, so users only see their own data.
- **Guest chat:** Sending/reading messages is tied to `guestEmail` matching the conversation, so only that “guest” can use that thread.

**What to fix or harden**

| Issue | Risk | What to do |
|-------|------|------------|
| **CORS “AllowAll”** | Any site can call your API from the browser. | In production, restrict to your frontend origin(s), e.g. `WithOrigins("https://your-app.com")`. |
| **JWT secret in appsettings** | If repo or server is leaked, tokens can be forged. | Use env vars or a secret manager (e.g. Azure Key Vault); never commit real secrets. |
| **Connection string / DB password** | Same as above. | Keep out of repo; use env or secret store. Use least-privilege DB user. |
| **No rate limiting** | Login, forgot-password, guest conversation creation, and public endpoints can be brute-forced or spammed. | Add rate limiting (e.g. AspNetCoreRateLimit or cloud gateway) on auth and public endpoints. |
| **Upload endpoint has no auth** | Anyone can upload up to 5 MB. | For production, require auth (e.g. Vendor) for upload, or at least a simple API key / captcha for anonymous. |
| **Guest chat identity** | Anyone who knows `conversationId` + `guestEmail` can read/send. | Acceptable for “link by email”; optionally add rate limit per email/conversation and consider short-lived tokens for guest sessions later. |
| **Swagger in production** | Exposes all endpoints and shapes. | Disable or protect Swagger when not in Development (e.g. `if (app.Environment.IsDevelopment())` only). |
| **HTTPS** | You have `UseHttpsRedirection()`. | Ensure production host enforces HTTPS and HSTS. |

So: **foundation is secure enough for development and a first release**, but before going live you should tighten CORS, secrets, rate limiting, upload auth, and Swagger.

---

## 3. What to improve (senior-dev view)

**High impact**

1. **Environment-based config**  
   Use `appsettings.Development.json` vs `appsettings.Production.json` (and env vars) for connection strings, JWT secret, CORS, and “is production” flags. Never commit production secrets.

2. **Rate limiting**  
   Apply to: login, forgot-password, resend-verification, and public endpoints (e.g. guest conversation, guest order). Reduces abuse and brute force.

3. **Real email (and optional SMS)**  
   Plug in a real provider for verification and password reset. Optionally add retry and a dead-letter log.

4. **Notifications**  
   Add `Notification` entity and API so the dashboard “Notifications” screen is backed by real data and “mark read” works.

**Medium impact**

5. **Structured logging**  
   Use something like Serilog with request id and user id so you can trace a request and audit important actions.

6. **Validation**  
   You already use DTOs and attributes; add a global filter or FluentValidation for complex rules and consistent error messages.

7. **Health check**  
   Add `MapHealthChecks("/health")` and check DB (and optional dependencies) so hosting/load balancers can see if the app is up.

8. **Pagination metadata**  
   For list endpoints (products, orders, messages), return total count or “has more” so the frontend can build proper pagination.

**Nice to have**

9. **Refresh token rotation**  
   On refresh, issue a new refresh token and invalidate the old one to limit damage if a token is stolen.

10. **Audit fields**  
    e.g. `CreatedBy`, `UpdatedBy` or at least `UpdatedAt` on important tables for support and debugging.

11. **API versioning**  
    e.g. `/api/v1/...` so you can introduce breaking changes under v2 later.

12. **Request/response logging (PII-safe)**  
    Log method, path, status, duration; avoid logging full bodies or tokens.

---

## 4. Quick checklist before “go live”

- [ ] JWT secret and DB connection string from env or secret manager, not in repo.
- [ ] CORS restricted to your frontend origin(s).
- [ ] Rate limiting on auth and public endpoints.
- [ ] Real email (and optionally SMS) for verification and password reset.
- [ ] Upload requires auth or is otherwise protected.
- [ ] Swagger disabled or restricted in production.
- [ ] HTTPS and HSTS enforced in production.
- [ ] Run `AddGuestBuyerSupport.sql` (and any other migration scripts) on production DB if not using EF migrations.
- [ ] (Optional) Notifications API and analytics tracking if you want those screens to be real.

---

**Summary:** The app is in good shape for development and a first release: auth, hashing, parameterized DB access, and scoped vendor data are in place. To be “secure and production-ready,” focus on: secrets, CORS, rate limiting, real email, and locking down upload and Swagger. The main functional gap is **Notifications**; the rest is hardening and operational improvements.
