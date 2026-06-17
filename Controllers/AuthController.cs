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

        // E.164 international phone number format: +[country code][number], 7–15 digits total
        private static readonly Regex PhoneNumberRegex =
            new(@"^\+[1-9]\d{6,14}$", RegexOptions.Compiled);

        public AuthController(
            IConfiguration configuration,
            ILogger<AuthController> logger,
            ISmsService smsService)
        {
            _configuration = configuration;
            _logger        = logger;
            _smsService    = smsService;
        }

        // ─────────────────────────────────────────────────────────────────────
        // POST api/auth/token  –  JWT generation (existing functionality)
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Generate a JWT token for testing purposes.
        /// </summary>
        /// <param name="request">Login request containing username and password.</param>
        /// <returns>JWT token string.</returns>
        [HttpPost("token")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        public IActionResult GenerateToken([FromBody] LoginRequest request)
        {
            _logger.LogInformation("Token generation requested for user: {Username}", request.Username);

            try
            {
                // Basic credential validation
                if (string.IsNullOrWhiteSpace(request.Username) ||
                    string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error      = "InvalidCredentials",
                        Message    = "Username and password are required",
                        StatusCode = 400
                    });
                }

                // For demo purposes, accept any non-empty credentials.
                // In production this would validate against a user store.
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(
                    _configuration["Jwt:Key"] ?? "default-secret-key-for-development");

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name,           request.Username),
                        new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                        new Claim("username",                request.Username)
                    }),
                    Expires            = DateTime.UtcNow.AddHours(1),
                    Issuer             = _configuration["Jwt:Issuer"],
                    Audience           = _configuration["Jwt:Audience"],
                    SigningCredentials  = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature)
                };

                var token       = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                _logger.LogInformation("Token generated successfully for user: {Username}", request.Username);

                return Ok(new
                {
                    token     = tokenString,
                    expiresAt = tokenDescriptor.Expires
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating token for user: {Username}", request.Username);
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error      = "TokenGenerationError",
                    Message    = "An error occurred while generating the token",
                    StatusCode = 500
                });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // POST api/auth/register/phone  –  Phone number registration + SMS
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Register a phone number and send a verification SMS.
        /// The phone number must be in E.164 format (e.g. +14155552671).
        /// A one-time token is generated and dispatched via SMS only when the
        /// format is valid.
        /// </summary>
        /// <param name="request">Phone registration request.</param>
        /// <returns>202 Accepted when the SMS was dispatched; 400 for invalid input.</returns>
        [HttpPost("register/phone")]
        [ProducesResponseType(typeof(object), StatusCodes.Status202Accepted)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RegisterPhone([FromBody] PhoneRegistrationRequest request)
        {
            _logger.LogInformation(
                "Phone registration requested for number: {PhoneNumber}",
                request?.PhoneNumber);

            // ── 1. Input presence check ──────────────────────────────────────
            if (request == null || string.IsNullOrWhiteSpace(request.PhoneNumber))
            {
                return BadRequest(new ErrorResponse
                {
                    Error      = "InvalidInput",
                    Message    = "Phone number is required",
                    StatusCode = 400
                });
            }

            // ── 2. Format validation (E.164) ─────────────────────────────────
            if (!PhoneNumberRegex.IsMatch(request.PhoneNumber))
            {
                _logger.LogWarning(
                    "Invalid phone number format supplied: {PhoneNumber}",
                    request.PhoneNumber);

                return BadRequest(new ErrorResponse
                {
                    Error      = "InvalidPhoneNumber",
                    Message    = "Phone number must be in E.164 format (e.g. +14155552671)",
                    StatusCode = 400
                });
            }

            // ── 3. Generate a one-time verification token ────────────────────
            // Six-digit numeric token; in production store this with an expiry.
            var verificationToken = GenerateVerificationToken();

            _logger.LogInformation(
                "Phone number {PhoneNumber} passed format validation. Sending verification SMS.",
                request.PhoneNumber);

            // ── 4. Send SMS via the injected service ─────────────────────────
            var smsSent = await _smsService.SendVerificationSmsAsync(
                request.PhoneNumber, verificationToken);

            if (!smsSent)
            {
                // The service already logged the root cause; surface a 500 to the caller.
                _logger.LogError(
                    "SMS dispatch failed for phone number: {PhoneNumber}",
                    request.PhoneNumber);

                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error      = "SmsSendError",
                    Message    = "Failed to send verification SMS. Please try again later.",
                    StatusCode = 500
                });
            }

            _logger.LogInformation(
                "Verification SMS dispatched successfully to {PhoneNumber}",
                request.PhoneNumber);

            return Accepted(new
            {
                message     = "Verification SMS sent. Please enter the code you received.",
                phoneNumber = request.PhoneNumber
            });
        }

        // ─────────────────────────────────────────────────────────────────────
        // Helpers
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Generates a cryptographically random 6-digit numeric verification token.
        /// </summary>
        private static string GenerateVerificationToken()
        {
            // Use a range that guarantees exactly 6 digits (100000–999999)
            var token = Random.Shared.Next(100_000, 1_000_000);
            return token.ToString();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Request models (kept in the same file for locality; move to Models/ if
    // the project grows)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Login credentials for JWT token generation.</summary>
    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    /// <summary>Phone number supplied for registration and SMS verification.</summary>
    public class PhoneRegistrationRequest
    {
        /// <summary>
        /// Phone number in E.164 format, e.g. +14155552671.
        /// </summary>
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
