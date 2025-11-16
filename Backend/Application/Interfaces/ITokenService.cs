
using Domain.Entities;
using System.Security.Claims;

namespace Application.Interfaces;
public interface ITokenService
{
    string GenerateToken(User user, int expirationMinutes = 60);
    string GenerateRefreshToken();
    bool ValidateRefreshToken(User user, string refreshToken);
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
}