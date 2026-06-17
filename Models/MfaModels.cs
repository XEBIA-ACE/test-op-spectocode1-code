namespace ApiGateway.Models
{
    /// <summary>
    /// Request model for the first-factor (username/password) login step.
    /// </summary>
    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    /// <summary>
    /// Request model for the second-factor (TOTP code) MFA verification step.
    /// </summary>
    public class MfaVerifyRequest
    {
        /// <summary>6-digit TOTP code from the authenticator app.</summary>
        public string Code { get; set; } = string.Empty;
    }

    /// <summary>
    /// Response returned after a successful MFA setup, containing the TOTP secret
    /// and a provisioning URI for QR-code generation.
    /// </summary>
    public class MfaSetupResponse
    {
        /// <summary>Base-32 encoded TOTP secret to be stored by the user's authenticator app.</summary>
        public string Secret { get; set; } = string.Empty;

        /// <summary>otpauth:// URI suitable for encoding as a QR code.</summary>
        public string ProvisioningUri { get; set; } = string.Empty;

        /// <summary>Human-readable issuer label shown in the authenticator app.</summary>
        public string IssuerName { get; set; } = string.Empty;
    }

    /// <summary>
    /// Response returned after a successful MFA verification, containing the
    /// fully-authenticated JWT (mfa_verified=true).
    /// </summary>
    public class MfaVerifyResponse
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
    }
}
