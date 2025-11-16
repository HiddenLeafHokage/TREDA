using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Application.Interfaces;

namespace Application.Services
{
    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;
    
    public EmailService(ILogger<EmailService> logger)
    {
        _logger = logger;
    }
    public async Task SendPasswordResetCodeAsync(string email, string resetCode)
    {
        try
        {
            // Log OTP code for development - Frontend can use this for testing
            _logger.LogInformation("🔐 PASSWORD RESET OTP for {Email}: {ResetCode}", email, resetCode);
            _logger.LogInformation("📧 Password reset email would be sent to: {Email}", email);
            
            // In production, this would send to WhatsApp/Email
            // For now, we log it so frontend can use the code for testing
            
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending password reset email to {Email}", email);
            throw new Exception("Failed to send password reset email. Please try again.");
        }
    }
    
    public async Task SendEmailVerificationCodeAsync(string email, string verificationCode)
    {
        try
        {
            // Log OTP code for development - Frontend can use this for testing
            _logger.LogInformation("✅ EMAIL VERIFICATION OTP for {Email}: {VerificationCode}", email, verificationCode);
            _logger.LogInformation("📧 Verification email would be sent to: {Email}", email);
            
            // In production, this would send to WhatsApp/Email
            // For now, we log it so frontend can use the code for testing
            
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending verification email to {Email}", email);
            throw new Exception("Failed to send verification email. Please try again.");
        }
    }
    
    public async Task SendWelcomeEmailAsync(string email, string businessName)
    {
        try
        {
            _logger.LogInformation("🎉 Welcome email would be sent to: {Email} for business: {BusinessName}", email, businessName);
            
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending welcome email to {Email}", email);
            // Don't throw for welcome emails - they're not critical
        }
    }
   
        
    }
}