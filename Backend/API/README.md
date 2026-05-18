# Treda API – Testing & Frontend Integration

Use this guide to run the API, test all endpoints in Swagger, and integrate with the frontend.

---

## Quick start (run the API)

1. **Prerequisites**
   - [.NET 9.0 SDK](https://dotnet.microsoft.com/download)
   - SQL Server (LocalDB, Express, or Developer Edition)

2. **Database**
   - First time or after code changes that add migrations:
     ```bash
     cd Backend/API
     dotnet ef database update --project ../Persistence
     ```
   - **Important:** If the API is running, **stop it** before running `dotnet ef` (to avoid "file in use" errors). After pulling the **ProductCategoriesAndVendorRename** migration, run `dotnet ef database update --project ../Persistence` once to create the categories table and switch Products to CategoryId/Condition/Location/VendorId.
   - **If you get "Invalid column name 'VendorId'"** when calling vendor dashboard or products: the migration did not apply. Stop the API and run `dotnet ef database update --project ../Persistence` again. If that still fails with "pending model changes", run the one-time SQL script **Backend/Persistence/Scripts/ApplyProductCategoriesAndVendorId.sql** against your database (e.g. in SQL Server Management Studio), then restart the API.
   - **Guest buyer support:** Run **Backend/Persistence/Scripts/AddGuestBuyerSupport.sql** once against TredaDB to add GuestEmail/GuestName and nullable BuyerId/SenderId (so buyers can chat and create orders without registering).

3. **Run**
   ```bash
   cd Backend/API
   dotnet run
   ```

4. **Open Swagger**
   - URL: **https://localhost:5001/swagger**
   - All API call points are listed there for testing and frontend integration.

---

## Testing in Postman (including profile)

To test **every** endpoint (including **GET /api/auth/profile**) in Postman:

1. Get a token: **POST** `/api/auth/login` (or register-vendor) → copy `data.token`.
2. For any protected request: **Authorization** tab → Type: **Bearer Token** → paste the token.
3. Send **GET** `/api/auth/profile` (and any other call).

Full step-by-step: **[POSTMAN_TESTING.md](POSTMAN_TESTING.md)**.

---

## Base URL & Swagger

| Item | Value |
|------|--------|
| **Base URL** | `https://localhost:5001` |
| **Swagger UI** | `https://localhost:5001/swagger` |
| **API prefix** | `/api` |

In Swagger you will see every endpoint. Use **Authorize** (top right) with a Bearer token from login/register to call protected endpoints.

---

## How to test protected endpoints in Swagger

1. Open **https://localhost:5001/swagger**.
2. Call **POST /api/auth/register-vendor** or **POST /api/auth/login** and copy `data.token` from the response.
3. Click **Authorize**.
4. Enter: `Bearer <paste-your-token>` (include the word `Bearer` and a space).
5. Click **Authorize**, then **Close**.
6. All subsequent requests in Swagger will send this token. You can now test every call point.

---

## Standard response format

All endpoints return a wrapper:

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "code": 0,
  "data": { ... },
  "timestamp": "2025-02-10T12:00:00Z"
}
```

- **Success:** `success: true`, `code: 0` (or 1 for created).
- **Error:** `success: false`, `code` = HTTP-style code (400, 401, 404, 409, 500). Frontend should use `code` and `message` for error handling.

---

## All API call points (for testing and frontend)

### Auth (`/api/auth`) – no token required unless noted

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/auth/test` | Health check | No |
| POST | `/api/auth/register-vendor` | Register vendor | No |
| POST | `/api/auth/login` | Login (returns token) | No |
| POST | `/api/auth/verify-email` | Verify email with OTP | No |
| POST | `/api/auth/resend-verification-email` | Resend verification code (e.g. if deleted/lost) | No |
| POST | `/api/auth/forgot-password` | Request password reset | No |
| POST | `/api/auth/verify-reset-code` | Verify reset code | No |
| POST | `/api/auth/reset-password` | Reset password with code | No |
| POST | `/api/auth/refresh-token` | Refresh JWT | No |
| POST | `/api/auth/google-login` | Google login (not implemented) | No |
| GET | `/api/auth/profile` | Current user profile | **Bearer** |

---

### Upload (`/api/upload`) – no auth (or add Bearer if you want)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload file (form-data, key `file`). Allowed: .jpg, .jpeg, .png, .gif, .webp, .pdf. Max 5 MB. Returns `{ data: { url, fileName } }`. Use `url` (e.g. `/uploads/xxx`) – prepend API base URL for full URL. |

---

### Categories (`/api/categories`) – no auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/categories` | List all product categories (Jiji-style). Use `id` when creating/updating a product. |

---

### Buyer – no registration (`/api/public`) – **no auth**

Customers can browse, contact seller via chat, and create orders/invoices **without registering**.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/public/products` | Browse products (query: `search`, `categoryId`, `page`, `pageSize`) |
| GET | `/api/public/products/{id}` | Product detail **with seller contact info** (name, email, phone, business) |
| POST | `/api/public/conversations` | Guest starts chat (body: `vendorId`, `productId?`, `guestName`, `guestEmail`) |
| GET | `/api/public/conversations/{id}/messages` | Guest loads messages (query: `guestEmail`, `page`, `pageSize`) |
| POST | `/api/public/conversations/{id}/messages` | Guest sends message (body: `guestEmail`, `content`) |
| POST | `/api/public/orders` | Guest creates order/invoice (body: `vendorId`, `productId?`, `guestName`, `guestEmail`, `amount`, `message?`) |

---

### Vendor dashboard & profile (`/api/vendor`) – **Bearer (Vendor/Admin)**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vendor/profile` | Get vendor/shop profile |
| PUT | `/api/vendor/profile` | Update vendor/shop profile |
| GET | `/api/vendor/dashboard/stats` | Dashboard stats (Total Sales, Orders Today, Pending, Wallet) |
| GET | `/api/vendor/dashboard/orders` | Recent orders (query: `from`, `to`) |
| GET | `/api/vendor/dashboard/best-selling` | Best selling products (query: `limit`) |
| GET | `/api/vendor/dashboard/analytics` | Performance (sales by day), Favourites/Views/etc. (query: `lastDays`) |

---

### Products (`/api/products`) – **Bearer (Vendor/Admin)**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/products` | List my products (query: `search`, `categoryId`, `page`, `pageSize` for table view) |
| GET | `/api/products/{id}` | Get one product |
| POST | `/api/products` | Create product |
| PUT | `/api/products/{id}` | Update product |
| DELETE | `/api/products/{id}` | Delete product |

---

### Orders (`/api/orders`) – **Bearer (Vendor/Admin)**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/orders` | List orders (query: `from`, `to` **or** `search`, `status`, `page`, `pageSize`) |
| GET | `/api/orders/{id}` | Get one order |
| POST | `/api/orders` | Create order (for registered buyer; body can include `guestEmail`+`guestName` for guest) |
| PUT | `/api/orders/{id}/status` | Update order status |
| PUT | `/api/orders/{id}` | **Negotiate invoice**: update `amount` and/or `status` (body: `amount?`, `status?`) |

---

### Wallet (`/api/vendor/wallet`) – **Bearer (Vendor/Admin)**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vendor/wallet/balance` | Wallet balance |
| GET | `/api/vendor/wallet/transactions` | Transaction history (query: `page`, `pageSize`) |
| POST | `/api/vendor/wallet/promote/{productId}` | Promote listing (Treda Ads) |

---

### Messages / Chat (`/api/messages` and `/api/public`) – **Vendor: Bearer; Guest: no auth**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/messages/conversations` | List my conversations (vendor, Bearer) |
| GET | `/api/messages/conversations/{id}/messages` | Get messages (vendor or registered buyer, Bearer) |
| POST | `/api/messages/conversations/{id}/messages` | Send message (vendor or registered buyer, Bearer) |
| POST | `/api/messages/conversations` | Get or create conversation (body: vendorId + buyerId + productId) (Bearer) |
| **Guest (no auth):** POST `/api/public/conversations`, GET/POST `/api/public/conversations/{id}/messages` | See "Buyer – no registration" table above |

---

## Request body examples (for Swagger / frontend)

### POST /api/auth/login
```json
{
  "email": "vendor@example.com",
  "password": "YourPassword1!",
  "rememberMe": false
}
```

### POST /api/auth/register-vendor
- `fullName`, `businessName`, `email`, `phoneNumber`, `password`, `confirmPassword`
- `businessCategory`, `businessLocation`, `shopDescription`, `deliveryMethod`, `cac_RC_Number`
- `businessLogoUrl` (optional)
- **deliveryMethod:** `1` = PickupOnly, `2` = DeliveryOnly, `3` = Both  
- **cac_RC_Number:** format `RC-123456`
- **phoneNumber:** One phone per account. Accepted formats: `+2348012345678`, `09012345678`, etc. If the number is already used by another account, registration/update returns conflict.
- **Flow: Register → Verify email → Login.** Login is allowed only after email is verified. Verification code expires in **45 minutes**; use **POST /api/auth/resend-verification-email** with `{ "email": "..." }` to get a new code (only if not yet verified; if already verified, API returns "Email is already verified").

### GET /api/categories (list categories)
No body. Returns list of categories with `id`, `name`, `slug`, `description`, `displayOrder`. Use `id` (e.g. `cat-phones`, `cat-electronics`) in product create/update.

### POST /api/products (create product – full info, Jiji-style)
```json
{
  "name": "Product name",
  "description": "Full description",
  "price": 99.99,
  "categoryId": "cat-phones",
  "condition": 0,
  "location": "Lagos, Ikeja",
  "imageUrls": ["https://example.com/1.jpg"],
  "stockQuantity": 10,
  "isActive": true
}
```
- **categoryId:** From GET /api/categories (e.g. `cat-phones`, `cat-electronics`, `cat-food`, `cat-accessories`).
- **condition:** `0` = New, `1` = Used, `2` = Refurbished.
- **location:** City/area for pickup (optional).
- To **put out of stock** or hide: use **PUT** `/api/products/{id}` with `"isActive": false` and/or `"stockQuantity": 0`.

### POST /api/orders (create order/inquiry)
```json
{
  "buyerId": "buyer-user-guid",
  "productId": "product-guid-or-null",
  "amount": 850000,
  "customerName": "Customer Name"
}
```

### PUT /api/orders/{id}/status
```json
{
  "status": 0
}
```
- **status:** `0` Pending, `1` Contacted, `2` Shipped, `3` Completed, `4` Cancelled

### POST /api/vendor/wallet/promote/{productId} (Treda Ads)
```json
{
  "amount": 5000,
  "durationDays": 7
}
```

### PUT /api/vendor/profile
- `businessCategory`, `businessLocation`, `shopDescription`, `deliveryMethod`, `cac_RC_Number`
- `businessLogoUrl` (optional)

### POST /api/messages/conversations (get or create)
- **Vendor starting chat with buyer:** `{ "vendorId": "<vendor-id>", "buyerId": "<buyer-id>", "productId": "<product-id-or-null>" }`
- **Buyer starting chat with vendor:** same body; ensure `vendorId` is the vendor and `buyerId` is the current user (buyer).

### POST /api/messages/conversations/{id}/messages
```json
{
  "content": "Hello, I am interested in this product."
}
```

---

## Query parameters (frontend)

- **Dashboard orders / Orders list:** `from`, `to` (ISO date, e.g. `2025-01-08`, `2025-02-02`)
- **Best selling:** `limit` (default 10)
- **Wallet transactions / Messages:** `page`, `pageSize` (defaults 1, 20 or 50)

---

## Frontend integration checklist

1. **Base URL:** `https://localhost:5001` (or your deployed URL).
2. **Headers:**  
   - `Content-Type: application/json`  
   - `Authorization: Bearer <token>` for all endpoints except auth (and auth/profile).
3. **Login flow:** Call `POST /api/auth/login`, store `data.token` (and optionally `data.refreshToken`), send token in `Authorization` for every request.
4. **Errors:** Use `success`, `code`, and `message` from the response body; do not rely only on HTTP status.
5. **CORS:** API allows all origins in development; frontend can call from any origin during dev.
6. **All call points:** Listed above and visible in **Swagger** at `https://localhost:5001/swagger` — use it as the single reference for testing and integrating.

---

## Response codes (for frontend)

| Code | Meaning |
|------|--------|
| 0 | Success |
| 1 | Created |
| 400 | Validation error |
| 401 | Unauthorized (invalid/expired token) |
| 403 | Forbidden (wrong role) |
| 404 | Not found |
| 409 | Conflict (e.g. duplicate email) |
| 500 | Server error |

---

## Summary

- Run: `dotnet run` from `Backend/API`.
- Open **https://localhost:5001/swagger** to see and test every call point.
- Use **Authorize** with `Bearer <token>` (from login/register) to test protected endpoints.
- Share this README and the Swagger URL with the frontend developer so they can test and integrate the API; all call points are available in Swagger.
