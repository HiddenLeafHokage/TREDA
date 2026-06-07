using System.Net;
using System.Net.Mail;
using Application.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Application.Services;

public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;
    private readonly string _smtpUser;
    private readonly string _smtpPassword;
    private readonly string _fromAddress;
    private readonly string _fromName;
    private readonly bool _isConfigured;

    public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
    {
        _logger = logger;

        _smtpUser     = configuration["Email:SmtpUser"]     ?? string.Empty;
        _smtpPassword = configuration["Email:SmtpPassword"] ?? string.Empty;
        _fromAddress  = configuration["Email:FromAddress"]  ?? _smtpUser;
        _fromName     = configuration["Email:FromName"]     ?? "Treda";
        _isConfigured = !string.IsNullOrWhiteSpace(_smtpUser) && !string.IsNullOrWhiteSpace(_smtpPassword);

        if (!_isConfigured)
            _logger.LogWarning("Gmail SMTP not configured — emails will only be logged. Set Email__SmtpUser and Email__SmtpPassword env vars.");
    }

    public async Task SendEmailVerificationCodeAsync(string email, string verificationCode)
    {
        await SendAsync(email, "Verify your Treda account", BuildVerificationEmail(verificationCode));
        _logger.LogInformation("Verification email dispatched to {Email}", email);
    }

    public async Task SendPasswordResetCodeAsync(string email, string resetCode)
    {
        await SendAsync(email, "Reset your Treda password", BuildPasswordResetEmail(resetCode));
        _logger.LogInformation("Password reset email dispatched to {Email}", email);
    }

    public async Task SendWelcomeEmailAsync(string email, string businessName)
    {
        await SendAsync(email, $"Welcome to Treda, {businessName}!", BuildWelcomeEmail(businessName));
        _logger.LogInformation("Welcome email dispatched to {Email}", email);
    }

    // ── Core send ─────────────────────────────────────────────────────────────

    private async Task SendAsync(string toEmail, string subject, string htmlBody)
    {
        if (!_isConfigured)
        {
            _logger.LogInformation(
                "[EMAIL NOT SENT — SMTP not configured] To={Email} Subject={Subject}",
                toEmail, subject);
            return;
        }

        using var client = new SmtpClient("smtp.gmail.com", 587)
        {
            EnableSsl            = true,
            Credentials          = new NetworkCredential(_smtpUser, _smtpPassword),
            DeliveryMethod       = SmtpDeliveryMethod.Network,
            Timeout              = 15_000
        };

        using var message = new MailMessage
        {
            From       = new MailAddress(_fromAddress, _fromName),
            Subject    = subject,
            Body       = htmlBody,
            IsBodyHtml = true
        };
        message.To.Add(toEmail);

        try
        {
            await client.SendMailAsync(message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Gmail SMTP failed sending to {Email}", toEmail);
            throw new InvalidOperationException($"Email delivery failed: {ex.Message}", ex);
        }
    }

    // ── Templates ─────────────────────────────────────────────────────────────

    private static string BuildVerificationEmail(string code) => $"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
        <body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
            <tr><td align="center">
              <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
                <tr><td style="background:#1a1a2e;padding:32px;text-align:center;">
                  <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">Treda</h1>
                  <p style="margin:4px 0 0;color:#a0a0b0;font-size:13px;">Connect. Sell. Grow.</p>
                </td></tr>
                <tr><td style="padding:40px 32px;">
                  <h2 style="margin:0 0 8px;color:#111827;font-size:20px;">Verify your email address</h2>
                  <p style="margin:0 0 32px;color:#6b7280;font-size:15px;line-height:1.6;">Enter the code below to activate your Treda account.</p>
                  <div style="background:#f9fafb;border:2px dashed #e5e7eb;border-radius:12px;padding:28px;text-align:center;margin-bottom:32px;">
                    <p style="margin:0 0 8px;color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Verification code</p>
                    <p style="margin:0;color:#111827;font-size:40px;font-weight:700;letter-spacing:12px;">{code}</p>
                  </div>
                  <p style="margin:0;color:#9ca3af;font-size:13px;">Expires in <strong>45 minutes</strong>. Didn't create an account? Ignore this email.</p>
                </td></tr>
                <tr><td style="background:#f9fafb;padding:20px 32px;border-top:1px solid #f3f4f6;text-align:center;">
                  <p style="margin:0;color:#9ca3af;font-size:12px;">© 2026 Treda. All rights reserved.</p>
                </td></tr>
              </table>
            </td></tr>
          </table>
        </body></html>
        """;

    private static string BuildPasswordResetEmail(string code) => $"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
        <body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
            <tr><td align="center">
              <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
                <tr><td style="background:#1a1a2e;padding:32px;text-align:center;">
                  <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">Treda</h1>
                  <p style="margin:4px 0 0;color:#a0a0b0;font-size:13px;">Connect. Sell. Grow.</p>
                </td></tr>
                <tr><td style="padding:40px 32px;">
                  <h2 style="margin:0 0 8px;color:#111827;font-size:20px;">Reset your password</h2>
                  <p style="margin:0 0 32px;color:#6b7280;font-size:15px;line-height:1.6;">Use the code below to reset your password.</p>
                  <div style="background:#fff7ed;border:2px dashed #fed7aa;border-radius:12px;padding:28px;text-align:center;margin-bottom:32px;">
                    <p style="margin:0 0 8px;color:#9a3412;font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Reset code</p>
                    <p style="margin:0;color:#111827;font-size:40px;font-weight:700;letter-spacing:12px;">{code}</p>
                  </div>
                  <p style="margin:0;color:#9ca3af;font-size:13px;">Expires in <strong>45 minutes</strong>. Didn't request this? Your account is safe.</p>
                </td></tr>
                <tr><td style="background:#f9fafb;padding:20px 32px;border-top:1px solid #f3f4f6;text-align:center;">
                  <p style="margin:0;color:#9ca3af;font-size:12px;">© 2026 Treda. All rights reserved.</p>
                </td></tr>
              </table>
            </td></tr>
          </table>
        </body></html>
        """;

    private static string BuildWelcomeEmail(string businessName) => $"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
        <body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
            <tr><td align="center">
              <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
                <tr><td style="background:#1a1a2e;padding:32px;text-align:center;">
                  <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">Treda</h1>
                  <p style="margin:4px 0 0;color:#a0a0b0;font-size:13px;">Connect. Sell. Grow.</p>
                </td></tr>
                <tr><td style="padding:40px 32px;text-align:center;">
                  <div style="font-size:48px;margin-bottom:16px;">🎉</div>
                  <h2 style="margin:0 0 12px;color:#111827;font-size:22px;">Welcome to Treda, {businessName}!</h2>
                  <p style="margin:0 0 32px;color:#6b7280;font-size:15px;line-height:1.6;">Your account is verified. Start listing products and connecting with buyers.</p>
                  <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
                    <tr><td style="background:#1a1a2e;border-radius:8px;padding:14px 32px;">
                      <a href="https://app-treda.vercel.app" style="color:#fff;font-size:15px;font-weight:600;text-decoration:none;">Go to your dashboard →</a>
                    </td></tr>
                  </table>
                </td></tr>
                <tr><td style="background:#f9fafb;padding:20px 32px;border-top:1px solid #f3f4f6;text-align:center;">
                  <p style="margin:0;color:#9ca3af;font-size:12px;">© 2026 Treda. All rights reserved.</p>
                </td></tr>
              </table>
            </td></tr>
          </table>
        </body></html>
        """;
}
