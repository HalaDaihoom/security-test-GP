using Api.Models.DTOs;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using System.Threading.Tasks;

public interface IEmailService
{
    Task SendEmailAsync(string toEmail, string subject, string body);
}

public class EmailService : IEmailService
{
    private readonly IConfiguration _config;
    
    private readonly EmailSettings _emailSettings;


    public EmailService(IConfiguration config, IOptions<EmailSettings> emailSettings)
    {
        _config = config;
        _emailSettings = emailSettings.Value;
    }
    public async Task SendEmailAsync(string toEmail, string subject, string body)
{
    var email = new MimeMessage();
    email.From.Add(MailboxAddress.Parse(_config["EmailSettings:Sender"]));
    email.To.Add(MailboxAddress.Parse(toEmail));
    email.Subject = subject;
    email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = body };

    using var smtp = new SmtpClient();
    await smtp.ConnectAsync("smtp.gmail.com", 587, MailKit.Security.SecureSocketOptions.StartTls);
    await smtp.AuthenticateAsync(
        _config["EmailSettings:Sender"],
        _config["EmailSettings:AppPassword"]
    );
    await smtp.SendAsync(email);
    await smtp.DisconnectAsync(true);
}
}
