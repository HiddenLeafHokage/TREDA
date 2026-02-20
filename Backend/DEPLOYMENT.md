# Deployment Guide for Treda Backend API

This guide explains how to deploy your Treda backend API to production hosting.

## 🎯 Hosting Options

### Option 1: Azure (Recommended for .NET apps)
**Best for**: Easy deployment, managed services, good .NET support

**Pros:**
- ✅ Easy deployment from Visual Studio/GitHub
- ✅ Azure SQL Database (managed, auto-backups)
- ✅ Azure App Service (scales automatically)
- ✅ Free tier available for testing
- ✅ Built-in SSL certificates
- ✅ Can be fast if you choose the right tier

**Cons:**
- ⚠️ Can be expensive at scale
- ⚠️ Requires Azure account

**Cost**: ~$13-55/month for basic setup (App Service + SQL Database)

**About Azure Speed**: Azure can be fast if you:
- Choose the right service tier (Basic/Standard, not Free)
- Use Azure SQL in the same region as your App Service
- Enable connection pooling

---

### Option 2: AWS (Amazon Web Services)
**Best for**: Large scale, enterprise applications

**Services:**
- **API**: AWS Elastic Beanstalk or EC2
- **Database**: AWS RDS (SQL Server)

**Pros:**
- ✅ Very scalable
- ✅ Good performance
- ✅ Many services available

**Cons:**
- ⚠️ More complex setup
- ⚠️ Can be expensive

**Cost**: ~$20-100/month for basic setup

---

### Option 3: DigitalOcean / Linode / Vultr
**Best for**: Budget-friendly, full control

**Setup:**
- **API**: Droplet/VPS (Ubuntu/Linux)
- **Database**: SQL Server on Linux or PostgreSQL

**Pros:**
- ✅ Very affordable ($6-12/month)
- ✅ Full control over server
- ✅ Good performance
- ✅ Simple pricing

**Cons:**
- ⚠️ You manage everything (updates, security, backups)
- ⚠️ Requires Linux/DevOps knowledge

**Cost**: ~$6-20/month

---

### Option 4: Railway / Render / Fly.io
**Best for**: Easy deployment, modern platforms

**Pros:**
- ✅ Very easy deployment (Git push)
- ✅ Free tier available
- ✅ Automatic SSL
- ✅ Managed databases

**Cons:**
- ⚠️ Less control
- ⚠️ Can be expensive at scale

**Cost**: Free tier available, then ~$5-25/month

---

## 🚀 Recommended: Azure Deployment (Step-by-Step)

### Prerequisites
1. Azure account (free tier available)
2. Visual Studio 2022 or Azure CLI

### Step 1: Create Azure SQL Database

1. Go to [Azure Portal](https://portal.azure.com)
2. Create new resource → "SQL Database"
3. Choose:
   - **Server**: Create new (choose region close to you)
   - **Database name**: `TredaDB`
   - **Pricing tier**: Basic ($5/month) or Standard S0 ($15/month)
   - **Authentication**: SQL Authentication
4. Save the connection string (you'll need it)

**Connection String Format:**
```
Server=tcp:your-server.database.windows.net,1433;Initial Catalog=TredaDB;Persist Security Info=False;User ID=your-username;Password=your-password;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
```

### Step 2: Create Azure App Service

1. In Azure Portal → Create new resource → "Web App"
2. Choose:
   - **Name**: `treda-api` (or your choice)
   - **Runtime**: .NET 9.0
   - **Region**: Same as your SQL Database
   - **Pricing tier**: Free (for testing) or Basic B1 ($13/month)
3. Click "Create"

### Step 3: Configure App Settings

1. Go to your App Service → Configuration → Application settings
2. Add these settings:

```
ASPNETCORE_ENVIRONMENT = Production

ConnectionStrings__DefaultConnection = Server=tcp:your-server.database.windows.net,1433;Initial Catalog=TredaDB;User ID=your-username;Password=your-password;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;

Jwt__Secret = your-production-jwt-secret-min-32-characters
Jwt__Issuer = treda-api
Jwt__Audience = treda-client

Cors__AllowedOrigins__0 = https://your-frontend-domain.com
Cors__AllowedOrigins__1 = https://www.your-frontend-domain.com
```

### Step 4: Deploy Your Code

**Option A: Deploy from Visual Studio**
1. Right-click API project → Publish
2. Choose "Azure" → "Azure App Service"
3. Select your App Service
4. Click "Publish"

**Option B: Deploy from GitHub (CI/CD)**
1. Push code to GitHub
2. In Azure Portal → App Service → Deployment Center
3. Connect to GitHub
4. Select your repository
5. Azure will auto-deploy on every push

### Step 5: Run Database Migrations

After deployment, run migrations:

```bash
# Using Azure Cloud Shell or local terminal
dotnet ef database update --project Backend/Persistence --connection "YOUR_AZURE_SQL_CONNECTION_STRING"
```

Or use Azure Portal → App Service → Console:
```bash
cd site/wwwroot
dotnet ef database update
```

---

## 🔧 Alternative: VPS Deployment (DigitalOcean/Linode)

### Step 1: Create VPS
1. Create Ubuntu 22.04 server ($6-12/month)
2. Note your server IP address

### Step 2: Setup Server (SSH into server)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install .NET 9.0 SDK
wget https://dot.net/v1/dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 9.0

# Install SQL Server (optional, or use PostgreSQL)
# Or use managed database service

# Install Nginx (reverse proxy)
sudo apt install nginx -y

# Install systemd service for your API
```

### Step 3: Deploy Application

```bash
# Clone your repository
git clone https://github.com/your-username/treda.git
cd treda/Backend/API

# Build and publish
dotnet publish -c Release -o /var/www/treda-api

# Create systemd service
sudo nano /etc/systemd/system/treda-api.service
```

**Service file content:**
```ini
[Unit]
Description=Treda API
After=network.target

[Service]
Type=notify
ExecStart=/usr/bin/dotnet /var/www/treda-api/API.dll
Restart=always
RestartSec=10
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=http://localhost:5000

[Install]
WantedBy=multi-user.target
```

```bash
# Start service
sudo systemctl enable treda-api
sudo systemctl start treda-api

# Configure Nginx
sudo nano /etc/nginx/sites-available/treda-api
```

**Nginx config:**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection keep-alive;
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/treda-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Setup SSL with Let's Encrypt
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

---

## 🔐 Security Checklist for Production

- [ ] Change JWT secret to strong random string (min 32 characters)
- [ ] Use HTTPS only (SSL certificate)
- [ ] Configure CORS to allow only your frontend domain
- [ ] Use environment variables for secrets (never commit to Git)
- [ ] Enable database backups
- [ ] Set up monitoring/logging
- [ ] Configure firewall rules
- [ ] Use strong database passwords
- [ ] Disable Swagger in production (or password protect it)
- [ ] Set up rate limiting

---

## 📊 Performance Tips

1. **Database Connection Pooling**: Already enabled by EF Core
2. **Caching**: Consider adding Redis for session/token caching
3. **CDN**: Use CloudFlare or Azure CDN for static assets
4. **Database Indexing**: Already configured in your DbContext
5. **Async Operations**: Your code already uses async/await ✅

---

## 🧪 Testing Your Deployment

1. **Health Check Endpoint**: Add to test if API is running
2. **Test Authentication**: Try login/register endpoints
3. **Check Logs**: Monitor application logs for errors
4. **Performance Test**: Use tools like Apache Bench or Postman

---

## 💰 Cost Comparison

| Option | Monthly Cost | Difficulty | Best For |
|--------|-------------|------------|----------|
| Azure | $13-55 | Easy | .NET developers |
| AWS | $20-100 | Medium | Enterprise |
| DigitalOcean | $6-20 | Medium | Budget-conscious |
| Railway/Render | $5-25 | Very Easy | Quick deployment |
| Your Computer | $0 | N/A | Development only |

---

## 🆘 Troubleshooting

### Database Connection Issues
- Check firewall rules (Azure SQL requires IP whitelist)
- Verify connection string format
- Check if database server is running

### CORS Errors
- Verify `Cors:AllowedOrigins` in appsettings
- Check frontend URL matches exactly

### 500 Errors
- Check application logs in Azure Portal
- Verify all environment variables are set
- Check database migrations are applied

---

## 📝 Next Steps After Deployment

1. Set up monitoring (Application Insights, Sentry, etc.)
2. Configure automated backups
3. Set up CI/CD pipeline
4. Add health check endpoints
5. Configure rate limiting
6. Set up email service (SendGrid, AWS SES, etc.)

---

**Remember**: Start with a free/low-cost tier, then scale up as needed!


