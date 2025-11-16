using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Application.DTOs.Auth
{
    public class GoogleLoginDto
    {
        public string GoogleToken { get; set; } = string.Empty;
    }
}