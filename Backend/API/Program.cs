// API/Program.cs
using Application.Interfaces;
using Application.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Persistence.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Use InMemory database for testing
builder.Services.AddDbContext<TredaDbContext>(options =>
{
    options.UseInMemoryDatabase("TredaTestDB");
});

// Register services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<ITokenGenerator, TokenGenerator>();
builder.Services.AddScoped<IAuthService, AuthService>();

// Configure Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { 
        Title = "Treda API", 
        Version = "v1",
        Description = "API for Treda - Connect Sell Grow",
        Contact = new OpenApiContact
        {
            Name = "Treda Support",
            Email = "support@treda.com"
        }
    });
});




// Add logging
builder.Services.AddLogging();

// CORS
builder.Services.AddCors(options => 
    options.AddPolicy("AllowAll", policy => 
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));


var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseAuthorization();
app.MapControllers();

app.Run();