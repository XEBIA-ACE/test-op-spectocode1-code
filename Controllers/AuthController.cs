using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using ApiGateway.Models;
using ApiGateway.Services;

namespace ApiGateway.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;
        private readonly ISmsService _smsService;

        // E.164 international phone number format: +[country code][number], 7-15 digits total.
        private static readonly Regex PhoneNumberRegex =
            new(@"^\+[1-9]\d{6,14}$", RegexOptions.Compiled);

        public AuthController(
            IConfiguration configuration,
            ILogger<AuthController> logger,
            ISmsService smsService)
        {
            _configuration = configuration;
            _logger = logger;
            _smsService = smsService;
        }

        /// <summary>
        /// Generate JWT token for testing purposes.
        /// </summary>
        /// <param name="request">Login request</param>
        /// <returns>JWT token</returns>
        [HttpPost("token")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        public IActionResult GenerateToken([FromBody] LoginRequest request)
        {
            _logger.LogInformation("Token generation requested for user: {Username}", request.Username);

            try
            {
                // Simple validation for demo purposes
                if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error = "InvalidCredentials",
                        Message = "Username and password are required",
                        StatusCode = 400
                    });
                }

                // For demo purposes, accept any non-empty credentials.
                // In production, this would validate against a user store.
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(
                    _configuration["Jwt:Key"] ?? "default-secret-key-for-development");

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, request.Username),
                        new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                        new Claim("username", request.Username)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    Issuer = _configuration["Jwt:Issuer"],
                    Audience = _configuration["Jwt:Audience"],
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                _logger.LogInformation("Token generated successfully for user: {Username}", request.Username);

                return Ok(new
                {
                    token = tokenString,
                    expires = tokenDescriptor.Expires
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating token for user: {Username}", request.Username);
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "TokenGenerationFailed",
                    Message = "An error occurred while generating the token",
                    StatusCode = 500
                });
            }
        }

        /// <summary>
        /// Register a phone number and send a verification SMS.
        /// Validates the phone number format (E.164) before dispatching the SMS.
        /// </summary>
        /// <param name="request">Phone registration request containing the phone number.</param>
        /// <returns>200 OK when the SMS is dispatched; 400 for invalid format; 500 on send failure.</returns>
        [HttpPost("register/phone")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RegisterPhone([FromBody] PhoneRegistrationRequest request)
        {
            _logger.LogInformation("Phone registration requested for number: {PhoneNumber}", request.PhoneNumber);

            // Validate phone number format (E.164 international standard).
            if (string.IsNullOrWhiteSpace(request.PhoneNumber) ||
                !PhoneNumberRegex.IsMatch(request.PhoneNumber))
            {
                _logger.LogWarning(
                    "Invalid phone number format received: {PhoneNumber}", request.PhoneNumber);

                return BadRequest(new ErrorResponse
                {
                    Error = "InvalidPhoneNumber",
                    Message = "Phone number must be in E.164 format (e.g. +14155552671).",
                    StatusCode = 400
                });
            }

            // Phone number is valid — send verification SMS.
            const string verificationMessage =
                "Your verification code has been sent. Please use it to complete your registration.";

            var sent = await _smsService.SendSmsAsync(request.PhoneNumber, verificationMessage);

            if (!sent)
            {
                _logger.LogError(
                    "Failed to send verification SMS to {PhoneNumber}", request.PhoneNumber);

                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "SmsSendFailed",
                    Message = "Verification SMS could not be sent. Please try again later.",
                    StatusCode = 500
                });
            }

            _logger.LogInformation(
                "Verification SMS sent successfully to {PhoneNumber}", request.PhoneNumber);

            return Ok(new
            {
                message = "Verification SMS sent successfully.",
                phoneNumber = request.PhoneNumber
            });
        }
    }

    /// <summary>
    /// Login request model used by the token endpoint.
    /// </summary>
    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
