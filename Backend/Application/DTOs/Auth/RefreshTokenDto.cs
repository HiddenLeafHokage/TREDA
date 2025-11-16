using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Application.DTOs.Auth
{
    public class RefreshTokenDto
    {
        public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    }
}