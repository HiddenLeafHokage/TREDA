# Treda Backend API

A .NET 9.0 backend API for Treda - Connect Sell Grow platform.

## Testing & frontend integration

- **Full testing and integration guide (all call points):** [API/README.md](API/README.md)  
- **Swagger UI (all endpoints):** Run the API then open **https://localhost:5001/swagger**  
- Use **Authorize** in Swagger with `Bearer <token>` (from login/register) to test protected endpoints.

## Architecture

This project follows Clean Architecture principles with the following layers:

- **API**: Controllers and API configuration
- **Application**: Business logic, services, and DTOs
- **Domain**: Entities and enums
- **Persistence**: Database context and data access

## Prerequisites

- .NET 9.0 SDK
- SQL Server (LocalDB, Express, or Developer Edition) - **LOCAL, NOT CLOUD!**
- Visual Studio 2022 or VS Code (optional)

## Setup

1. **Install SQL Server (Local - Fast & Free)**
   - **Option 1: LocalDB** (Recommended - Lightweight, included with Visual Studio)
     - Already installed if you have Visual Studio
     - Connection string: `Server=(localdb)\\mssqllocaldb;Database=TredaDB;Trusted_Connection=true;TrustServerCertificate=true;`
   
   - **Option 2: SQL Server Express** (Full local server)
     - Download from [Microsoft](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
     - Free, runs on your computer
     - Connection string: `Server=localhost\\SQLEXPRESS;Database=TredaDB;Trusted_Connection=true;TrustServerCertificate=true;`
   
   - **Option 3: SQL Server Developer Edition** (Full features, free)
     - Best for development with all features
     - Download from [Microsoft](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)

2. **Configure Connection String**
   - Update `appsettings.json` with your SQL Server connection string:
   ```json
   {
     "ConnectionStrings": {
       "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=TredaDB;Trusted_Connection=true;TrustServerCertificate=true;"
     }
   }
   ```
   - **Note**: This is LOCAL SQL Server - runs on your computer, no cloud, no internet needed!

3. **Configure JWT Secret**
   - Update the JWT secret in `appsettings.json`:
   ```json
   {
     "Jwt": {
       "Secret": "your-super-secret-key-with-at-least-32-characters-change-in-production"
     }
   }
   ```
   ⚠️ **Important**: Change this to a secure random string in production!

4. **Create/Update Database (First Time or after migrations)**
   ```bash
   cd Backend/API
   dotnet ef database update --project ../Persistence
   ```
   - Creates or updates the database tables

5. **Restore Packages**
   ```bash
   dotnet restore
   ```

6. **Run the Application**
   ```bash
   cd Backend/API
   dotnet run
   ```

7. **Access Swagger UI**
   - Navigate to `https://localhost:5001/swagger` (or the port shown in console)

## API Endpoints

### Authentication
- `POST /api/auth/register-vendor` - Register a new vendor/seller
- `POST /api/auth/login` - User login
- `POST /api/auth/verify-email` - Verify email with OTP code
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/verify-reset-code` - Verify password reset code
- `POST /api/auth/reset-password` - Reset password with code
- `POST /api/auth/refresh-token` - Refresh JWT token
- `POST /api/auth/google-login` - Google OAuth login (not yet implemented)
- `GET /api/auth/profile` - Get user profile (requires authentication)

## Features

- ✅ JWT Authentication with refresh tokens
- ✅ Email verification (OTP-based)
- ✅ Password reset (OTP-based)
- ✅ Role-based authorization (Buyer, Seller, Admin)
- ✅ SQL Server database integration (Local - Fast & Free)
- ✅ Swagger API documentation
- ✅ CORS enabled for frontend integration

## Development Notes

- **Email Service**: Currently logs OTP codes to console for development. Check application logs for verification/reset codes.
- **Database**: Uses SQL Server (LOCAL - runs on your computer, not cloud). Fast, free, no internet required!
- **Authentication**: JWT tokens with configurable expiration

## Project Structure

```
Backend/
├── API/                 # Web API layer
│   ├── Controllers/     # API controllers
│   ├── Attributes/      # Custom attributes
│   └── Program.cs       # Application entry point
├── Application/         # Business logic layer
│   ├── DTOs/           # Data transfer objects
│   ├── Interfaces/     # Service interfaces
│   └── Services/        # Business logic services
├── Domain/             # Domain layer
│   ├── Entities/       # Domain entities
│   └── Enums/          # Domain enums
└── Persistence/        # Data access layer
    └── Data/           # DbContext and configurations
```

## Environment Variables

For production, consider using environment variables or Azure Key Vault for:
- SQL Server connection string (can still use local SQL Server or switch to cloud if needed)
- JWT secret key
- Email service credentials

## Why Local SQL Server?

✅ **Fast** - No network latency, runs on your computer  
✅ **Free** - SQL Server Express/Developer Edition is free  
✅ **No Internet Required** - Works offline  
✅ **Full Control** - You own the data  
✅ **Easy to Deploy** - Can deploy to cloud later if needed  

**Note**: You can always switch to Azure SQL later if you want cloud features, but for development, local SQL Server is recommended for speed and simplicity.

## License

Copyright © 2024 Treda
new 

