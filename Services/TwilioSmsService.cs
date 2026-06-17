using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace ApiGateway.Services
{
    /// <summary>
    /// Twilio-backed implementation of <see cref="ISmsService"/>.
    /// Credentials and sender number are read from the "Twilio" section of appsettings.
    /// </summary>
    public class TwilioSmsService : ISmsService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<TwilioSmsService> _logger;

        public TwilioSmsService(IConfiguration configuration, ILogger<TwilioSmsService> logger)
        {
            _configuration = configuration;
            _logger = logger;

            // Initialise the Twilio client once per service lifetime.
            var accountSid = _configuration["Twilio:AccountSid"]
                ?? throw new InvalidOperationException("Twilio:AccountSid is not configured.");
            var authToken = _configuration["Twilio:AuthToken"]
                ?? throw new InvalidOperationException("Twilio:AuthToken is not configured.");

            TwilioClient.Init(accountSid, authToken);
        }

        /// <inheritdoc />
        public async Task<bool> SendSmsAsync(string toPhoneNumber, string message)
        {
            var fromNumber = _configuration["Twilio:FromPhoneNumber"]
                ?? throw new InvalidOperationException("Twilio:FromPhoneNumber is not configured.");

            try
            {
                _logger.LogInformation("Sending SMS to {PhoneNumber}", toPhoneNumber);

                var messageResource = await MessageResource.CreateAsync(
                    to: new PhoneNumber(toPhoneNumber),
                    from: new PhoneNumber(fromNumber),
                    body: message
                );

                _logger.LogInformation(
                    "SMS dispatched successfully. SID: {MessageSid}, Status: {Status}",
                    messageResource.Sid,
                    messageResource.Status);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send SMS to {PhoneNumber}", toPhoneNumber);
                return false;
            }
        }
    }
}
