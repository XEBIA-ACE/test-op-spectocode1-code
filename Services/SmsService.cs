using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace ApiGateway.Services
{
    /// <summary>
    /// Twilio-backed SMS service.
    /// Configuration is read from the "Sms" section of appsettings.json:
    ///   "Sms": {
    ///     "AccountSid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ///     "AuthToken":  "your_auth_token",
    ///     "FromNumber": "+15005550006"   // Twilio test number or a purchased number
    ///   }
    /// </summary>
    public class SmsService : ISmsService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SmsService> _logger;

        // Message template sent to the user
        private const string MessageTemplate = "Your verification code is: {0}. It expires in 10 minutes.";

        public SmsService(IConfiguration configuration, ILogger<SmsService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<bool> SendVerificationSmsAsync(string phoneNumber, string token)
        {
            // Retrieve Twilio credentials from configuration
            var accountSid = _configuration["Sms:AccountSid"];
            var authToken  = _configuration["Sms:AuthToken"];
            var fromNumber = _configuration["Sms:FromNumber"];

            if (string.IsNullOrWhiteSpace(accountSid) ||
                string.IsNullOrWhiteSpace(authToken)  ||
                string.IsNullOrWhiteSpace(fromNumber))
            {
                _logger.LogError("SMS service is not configured correctly. " +
                                 "Ensure Sms:AccountSid, Sms:AuthToken, and Sms:FromNumber are set.");
                return false;
            }

            try
            {
                // Initialise the Twilio client (idempotent – safe to call multiple times)
                TwilioClient.Init(accountSid, authToken);

                var messageBody = string.Format(MessageTemplate, token);

                var message = await MessageResource.CreateAsync(
                    body: messageBody,
                    from: new PhoneNumber(fromNumber),
                    to:   new PhoneNumber(phoneNumber)
                );

                _logger.LogInformation(
                    "Verification SMS sent to {PhoneNumber}. Twilio SID: {MessageSid}, Status: {Status}",
                    phoneNumber, message.Sid, message.Status);

                return true;
            }
            catch (Twilio.Exceptions.ApiException ex)
            {
                // Twilio API-level errors (invalid number, account suspended, etc.)
                _logger.LogError(ex,
                    "Twilio API error while sending SMS to {PhoneNumber}. Code: {ErrorCode}",
                    phoneNumber, ex.Code);
                return false;
            }
            catch (Exception ex)
            {
                // Unexpected errors (network, serialisation, etc.)
                _logger.LogError(ex,
                    "Unexpected error while sending SMS to {PhoneNumber}",
                    phoneNumber);
                return false;
            }
        }
    }
}
