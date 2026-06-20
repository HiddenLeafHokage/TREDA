# Testing Treda API in Postman

Use this guide to test **all** endpoints in Postman, including the **profile** and protected routes.

---

## 1. Base URL

Set as an environment variable in Postman (optional):

- **Variable:** `baseUrl`
- **Value:** `https://localhost:5001`

Then use `{{baseUrl}}` in request URLs, e.g. `{{baseUrl}}/api/auth/login`.

Or use the full URL: `https://localhost:5001/api/...`

---

## 2. Get a token (login or register)

### Option A: Login (if you already have a vendor account)

1. **Method:** `POST`
2. **URL:** `https://localhost:5001/api/auth/login`
3. **Headers:** `Content-Type: application/json`
4. **Body (raw, JSON):**
   ```json
   {
     "email": "your-vendor@example.com",
     "password": "YourPassword1!",
     "rememberMe": false
   }
   ```
5. Send the request.
6. In the response body, copy the **token** from `data.token` (the long string).

### Option B: Register a new vendor

1. **Method:** `POST`
2. **URL:** `https://localhost:5001/api/auth/register-vendor`
3. **Headers:** `Content-Type: application/json`
4. **Body (raw, JSON):** Use the same shape as in Swagger (fullName, businessName, email, phoneNumber, password, confirmPassword, businessCategory, businessLocation, shopDescription, deliveryMethod, cac_RC_Number; optional businessLogoUrl).  
   **deliveryMethod:** `1` = PickupOnly, `2` = DeliveryOnly, `3` = Both.  
   **cac_RC_Number:** e.g. `RC-1234567`, `BN-4321`, `LLP-1234567`, `LP-12345`, or `IT-123`; 1-7 digits are accepted.
5. Send the request.
6. Copy `data.token` from the response.

Save the token somewhere (e.g. a Postman environment variable `token`) for the next step.

---

## 3. Test the profile endpoint (and any protected API)

1. **Method:** `GET`
2. **URL:** `https://localhost:5001/api/auth/profile`
3. **Headers:**
   - `Content-Type: application/json`
   - **Authorization:** `Bearer <paste-your-token-here>`
     - In Postman: go to the **Authorization** tab → Type: **Bearer Token** → paste the token in the **Token** field.  
     - Or in **Headers**: Key = `Authorization`, Value = `Bearer <your-token>`.
4. Send the request.

You should get `200 OK` with your profile (userId, userEmail, userName, userRole, emailVerified, businessName).

If you get **401 Unauthorized**, the token is missing, wrong, or expired. Get a new token from login/register and try again.

---

## 4. Use the same token for all protected endpoints

For every endpoint that requires auth (products, orders, vendor profile, wallet, messages, etc.):

- **Authorization** tab → Type: **Bearer Token** → Token: `<your-token>`

Or in **Headers**:

- **Key:** `Authorization`  
- **Value:** `Bearer <your-token>`

Then you can call:

- `GET {{baseUrl}}/api/auth/profile`
- `GET {{baseUrl}}/api/vendor/profile`
- `GET {{baseUrl}}/api/vendor/dashboard/stats`
- `GET {{baseUrl}}/api/products`
- `GET {{baseUrl}}/api/categories` (no auth)
- etc.

---

## 5. Quick checklist (all APIs)

| What you want to test | Method | URL | Auth |
|-----------------------|--------|-----|------|
| Health check | GET | `/api/auth/test` | No |
| Register vendor | POST | `/api/auth/register-vendor` | No |
| Login | POST | `/api/auth/login` | No |
| **Profile** | **GET** | **`/api/auth/profile`** | **Bearer token** |
| Vendor profile | GET | `/api/vendor/profile` | Bearer |
| Dashboard stats | GET | `/api/vendor/dashboard/stats` | Bearer |
| Categories (for product form) | GET | `/api/categories` | No |
| My products | GET | `/api/products` | Bearer |
| Create product | POST | `/api/products` | Bearer |
| Update product | PUT | `/api/products/{id}` | Bearer |
| Delete product | DELETE | `/api/products/{id}` | Bearer |
| My orders | GET | `/api/orders` | Bearer |
| Wallet balance | GET | `/api/vendor/wallet/balance` | Bearer |
| My conversations | GET | `/api/messages/conversations` | Bearer |

---

## 6. Common issues

- **401 on profile:** Add the `Authorization: Bearer <token>` header and ensure there is no typo or extra space. Token must be from login or register response `data.token`.
- **SSL certificate:** If Postman warns about HTTPS, you can turn off “SSL certificate verification” in Postman Settings for local testing only.
- **CORS:** Browsers may block cross-origin requests; Postman is not a browser, so CORS does not apply. If the same URL works in Postman but not in the browser, it’s a frontend CORS/config issue.

---

## 7. Summary

1. Get token: **POST** `/api/auth/login` (or register-vendor) → copy `data.token`.
2. In Postman, set **Authorization** to **Bearer Token** and paste that token.
3. Call **GET** `/api/auth/profile` (and any other endpoint) with that auth.

Once this works for profile, use the same token for all other protected endpoints when testing and before handing over to the frontend developer.
