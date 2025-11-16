// API/Attributes/SimpleAuthorizeAttribute.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace API.Attributes;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class SimpleAuthorizeAttribute : Attribute, IAuthorizationFilter
{
    private readonly string[] _allowedRoles;

    public SimpleAuthorizeAttribute(params string[] roles)
    {
        _allowedRoles = roles;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var token = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

        if (string.IsNullOrEmpty(token))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes("your-super-secret-key-with-at-least-32-characters-here-for-treda-app-2024");
            
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = "treda-api",
                ValidateAudience = true,
                ValidAudience = "treda-client",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out var validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var userRole = jwtToken.Claims.First(x => x.Type == ClaimTypes.Role).Value;

            // Check if user has required role
            if (_allowedRoles.Any() && !_allowedRoles.Contains(userRole))
            {
                context.Result = new ForbidResult();
                return;
            }

            // Add user to context for later use
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value),
                new Claim(ClaimTypes.Email, jwtToken.Claims.First(x => x.Type == ClaimTypes.Email).Value),
                new Claim(ClaimTypes.Name, jwtToken.Claims.First(x => x.Type == ClaimTypes.Name).Value),
                new Claim(ClaimTypes.Role, userRole)
            };

            var identity = new ClaimsIdentity(claims, "SimpleAuth");
            context.HttpContext.User = new ClaimsPrincipal(identity);
        }
        catch
        {
            context.Result = new UnauthorizedResult();
        }
    }
}