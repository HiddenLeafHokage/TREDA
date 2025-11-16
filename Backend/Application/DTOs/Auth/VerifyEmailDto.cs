using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Application.DTOs.Auth
{
    public class VerifyEmailDto
    {
         public string Email { get; set; } = string.Empty;
    public string VerificationCode { get; set; } = string.Empty;
    }
}