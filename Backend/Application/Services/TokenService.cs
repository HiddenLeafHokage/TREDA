// Application/Services/TokenService.cs
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Interfaces;
using Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Application.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _securityKey;
    private readonly string _issuer;
    private readonly string _audience;
    
    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
        var secretKey = _configuration["Jwt:Secret"] 
            ?? throw new InvalidOperationException("JWT Secret is not configured in appsettings.json");
        _securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        _issuer = _configuration["Jwt:Issuer"] ?? "treda-api";
        _audience = _configuration["Jwt:Audience"] ?? "treda-client";
    }
    
    public string GenerateToken(User user, int expirationMinutes = 60)
    {
        try
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.Role, user.UserType.ToString()),
                new Claim("EmailVerified", user.EmailVerified.ToString()),
                new Claim("BusinessName", user.BusinessName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            
            var creds = new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256);
            
            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: creds);
                
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        catch (Exception ex)
        {
            throw new Exception($"Error generating token: {ex.Message}");
        }
    }
    
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    
    public bool ValidateRefreshToken(User user, string refreshToken)
    {
        return user.RefreshToken == refreshToken &&
               user.RefreshTokenExpiryTime > DateTime.UtcNow;
    }

    public string GenerateRandomCode(int length = 6)
    {
        const string digits = "0123456789";
        var code = new char[length];
        var data = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(data);
        for (var i = 0; i < length; i++)
            code[i] = digits[data[i] % digits.Length];
        return new string(code);
    }
    
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _securityKey,
            ValidateLifetime = false // We don't validate lifetime here
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        
        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            
            if (securityToken is not JwtSecurityToken jwtSecurityToken || 
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            
            return principal;
        }
        catch (Exception)
        {
            throw new SecurityTokenException("Invalid token");
        }
    }
}