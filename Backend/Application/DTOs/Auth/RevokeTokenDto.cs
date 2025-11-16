using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Application.DTOs.Auth
{
    public class RevokeTokenDto
    {
        public string UserId { get; set; } = string.Empty;
    }
}