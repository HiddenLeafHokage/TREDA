using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Application.Interfaces;

namespace Application.Services
{
    public class TokenGenerator :ITokenGenerator
    {
        public string GenerateRandomCode(int length = 6)
    {
        const string digits = "0123456789";
        var code = new char[length];
        
        using (var rng = RandomNumberGenerator.Create())
        {
            var data = new byte[length];
            rng.GetBytes(data);
            
            for (int i = 0; i < length; i++)
            {
                code[i] = digits[data[i] % digits.Length];
            }
        }
        
        return new string(code);
    }
    
    public string GenerateSecureToken(int length = 32)
    {
        var randomNumber = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
        
    }
}