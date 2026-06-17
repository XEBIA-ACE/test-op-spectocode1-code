using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ApiGateway.Models;
using ApiGateway.Services;

namespace ApiGateway.Controllers
{
    /// <summary>
    /// Handles authentication and MFA operations.
    ///
    /// Flow:
    ///   1. POST /api/auth/token          – first-factor login; returns a step-1 JWT
    ///                                      (mfa_verified=false).
    ///   2. GET  /api/auth/mfa/setup      – (authenticated) returns TOTP secret +
    ///                                      provisioning URI for the authenticator app.
    ///   3. POST /api/auth/mfa/verify     – (authenticated) validates the TOTP code;
    ///                                      on success returns a fully-verified JWT
    ///                                      (mfa_verified=true).
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;
        private readonly IMfaService _mfaService;

        // In-memory store for demo purposes only.
        // Production code should persist secrets in a secure user store.
        private static readonly Dictionary<string, string> _userMfaSecrets = new(StringComparer.OrdinalIgnoreCase);

        public AuthController(
            IConfiguration configuration,
            ILogger<AuthController> logger,
            IMfaService mfaService)
        {
            _configuration = configuration;
            _logger = logger;
            _mfaService = mfaService;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 1 – First-factor login
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Validates username/password and returns a step-1 JWT.
        /// The token carries <c>mfa_verified=false</c> until the second factor
        /// is completed via <c>POST /api/auth/mfa/verify</c>.
        /// </summary>
        [HttpPost("token")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        public IActionResult GenerateToken([FromBody] LoginRequest request)
        {
            _logger.LogInformation("Token generation requested for user: {Username}", request.Username);

            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest(new ErrorResponse
                {
                    Error = "InvalidCredentials",
                    Message = "Username and password are required",
                    StatusCode = 400
                });
            }

            // Demo: accept any non-empty credentials.
            // Production: validate against a user store.
            var token = BuildJwt(request.Username, mfaVerified: false, expiryHours: 1);

            _logger.LogInformation("Step-1 token issued for user: {Username}", request.Username);

            return Ok(new
            {
                token,
                mfaRequired = true,
                message = "First-factor authentication successful. Complete MFA to obtain full access."
            });
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 2a – MFA setup (returns TOTP secret + provisioning URI)
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Returns a new TOTP secret and provisioning URI for the authenticated user.
        /// The caller should display the URI as a QR code for the authenticator app.
        /// </summary>
        [HttpGet("mfa/setup")]
        [Authorize]
        [ProducesResponseType(typeof(MfaSetupResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult MfaSetup()
        {
            var username = User.Identity?.Name ?? User.FindFirstValue("username") ?? "unknown";
            _logger.LogInformation("MFA setup requested for user: {Username}", username);

            var secret = _mfaService.GenerateSecret();

            // Persist the secret so it can be validated during verify
            _userMfaSecrets[username] = secret;

            var issuer = _configuration["Mfa:IssuerName"] ?? _configuration["Jwt:Issuer"] ?? "ApiGateway";
            var provisioningUri = _mfaService.GetProvisioningUri(secret, username, issuer);

            return Ok(new MfaSetupResponse
            {
                Secret = secret,
                ProvisioningUri = provisioningUri,
                IssuerName = issuer
            });
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 2b – MFA verification (validates TOTP code, issues full token)
        // ─────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Validates the 6-digit TOTP code supplied by the user.
        /// On success, returns a fully-authenticated JWT (<c>mfa_verified=true</c>).
        /// On failure, returns 401 – access is denied (spec AC).
        /// </summary>
        [HttpPost("mfa/verify")]
        [Authorize]
        [ProducesResponseType(typeof(MfaVerifyResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        public IActionResult MfaVerify([FromBody] MfaVerifyRequest request)
        {
            var username = User.Identity?.Name ?? User.FindFirstValue("username") ?? "unknown";
            _logger.LogInformation("MFA verification attempt for user: {Username}", username);

            if (string.IsNullOrWhiteSpace(request.Code))
            {
                return BadRequest(new ErrorResponse
                {
                    Error = "InvalidCode",
                    Message = "MFA code is required",
                    StatusCode = 400
                });
            }

            // Retrieve the stored secret for this user
            if (!_userMfaSecrets.TryGetValue(username, out var secret))
            {
                _logger.LogWarning("No MFA secret found for user: {Username}", username);
                return Unauthorized(new ErrorResponse
                {
                    Error = "MfaNotConfigured",
                    Message = "MFA has not been set up for this account. Call GET /api/auth/mfa/setup first.",
                    StatusCode = 401
                });
            }

            // Validate the TOTP code
            if (!_mfaService.ValidateCode(secret, request.Code))
            {
                _logger.LogWarning("Invalid MFA code provided for user: {Username}", username);
                // Spec AC: "when they provide an incorrect code, then access is denied"
                return Unauthorized(new ErrorResponse
                {
                    Error = "InvalidMfaCode",
                    Message = "The provided MFA code is incorrect or has expired.",
                    StatusCode = 401
                });
            }

            // Issue a fully-verified token
            var expiresAt = DateTime.UtcNow.AddHours(1);
            var token = BuildJwt(username, mfaVerified: true, expiryHours: 1);

            _logger.LogInformation("MFA verification successful for user: {Username}", username);

            return Ok(new MfaVerifyResponse
            {
                Token = token,
                ExpiresAt = expiresAt
            });
        }

        // ─────────────────────────────────────────────────────────────────────
        // Private helpers
        // ─────────────────────────────────────────────────────────────────────

        private string BuildJwt(string username, bool mfaVerified, int expiryHours)
        {
            var key = Encoding.UTF8.GetBytes(
                _configuration["Jwt:Key"] ?? "default-secret-key-for-development");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                    new Claim("username", username),
                    new Claim("mfa_verified", mfaVerified.ToString().ToLower())
                }),
                Expires = DateTime.UtcNow.AddHours(expiryHours),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateToken(tokenDescriptor);
            return handler.WriteToken(token);
        }
    }
}
