using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Application.Interfaces
{
    public interface IEmailService
    {
          Task SendPasswordResetCodeAsync(string email, string resetCode);
        Task SendEmailVerificationCodeAsync(string email, string verificationCode);
    Task SendWelcomeEmailAsync(string email, string businessName);
    }
}