using System.Security.Cryptography;
using System.Text;

namespace ApiGateway.Services
{
    /// <summary>
    /// Provides TOTP-based Multi-Factor Authentication operations:
    /// secret generation, provisioning URI construction, and code validation.
    ///
    /// Implements RFC 6238 (TOTP) using a 30-second time step and SHA-1 HMAC,
    /// which is compatible with Google Authenticator, Authy, and similar apps.
    /// </summary>
    public interface IMfaService
    {
        /// <summary>Generates a new cryptographically-random Base-32 TOTP secret.</summary>
        string GenerateSecret();

        /// <summary>
        /// Builds an otpauth:// provisioning URI for QR-code display.
        /// </summary>
        string GetProvisioningUri(string secret, string username, string issuer);

        /// <summary>
        /// Validates a 6-digit TOTP code against the supplied secret.
        /// Allows a ±1 time-step window to account for clock skew.
        /// </summary>
        bool ValidateCode(string secret, string code);
    }

    /// <inheritdoc />
    public class MfaService : IMfaService
    {
        // TOTP parameters (RFC 6238)
        private const int TimeStepSeconds = 30;
        private const int CodeDigits = 6;
        private const int AllowedDrift = 1; // ±1 time-step window

        private static readonly string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <inheritdoc />
        public string GenerateSecret()
        {
            // 20 bytes → 160-bit secret, standard for TOTP
            var bytes = RandomNumberGenerator.GetBytes(20);
            return ToBase32(bytes);
        }

        /// <inheritdoc />
        public string GetProvisioningUri(string secret, string username, string issuer)
        {
            var encodedIssuer = Uri.EscapeDataString(issuer);
            var encodedUser = Uri.EscapeDataString(username);
            return $"otpauth://totp/{encodedIssuer}:{encodedUser}" +
                   $"?secret={secret}&issuer={encodedIssuer}&algorithm=SHA1&digits={CodeDigits}&period={TimeStepSeconds}";
        }

        /// <inheritdoc />
        public bool ValidateCode(string secret, string code)
        {
            if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
                return false;

            if (code.Length != CodeDigits || !code.All(char.IsDigit))
                return false;

            var keyBytes = FromBase32(secret.ToUpperInvariant().TrimEnd('='));
            long currentStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TimeStepSeconds;

            for (int drift = -AllowedDrift; drift <= AllowedDrift; drift++)
            {
                var expected = ComputeTotp(keyBytes, currentStep + drift);
                if (expected == code)
                    return true;
            }

            return false;
        }

        // ── Internal TOTP computation (RFC 6238 / RFC 4226) ──────────────────

        private static string ComputeTotp(byte[] key, long timeStep)
        {
            // Counter as big-endian 8-byte array
            var counter = BitConverter.GetBytes(timeStep);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            using var hmac = new HMACSHA1(key);
            var hash = hmac.ComputeHash(counter);

            // Dynamic truncation
            int offset = hash[^1] & 0x0F;
            int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

            int otp = binary % (int)Math.Pow(10, CodeDigits);
            return otp.ToString().PadLeft(CodeDigits, '0');
        }

        // ── Base-32 helpers ───────────────────────────────────────────────────

        private static string ToBase32(byte[] data)
        {
            var sb = new StringBuilder();
            int buffer = 0, bitsLeft = 0;

            foreach (byte b in data)
            {
                buffer = (buffer << 8) | b;
                bitsLeft += 8;
                while (bitsLeft >= 5)
                {
                    bitsLeft -= 5;
                    sb.Append(Base32Alphabet[(buffer >> bitsLeft) & 0x1F]);
                }
            }

            if (bitsLeft > 0)
                sb.Append(Base32Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);

            return sb.ToString();
        }

        private static byte[] FromBase32(string input)
        {
            var output = new List<byte>();
            int buffer = 0, bitsLeft = 0;

            foreach (char c in input)
            {
                int value = Base32Alphabet.IndexOf(c);
                if (value < 0) continue; // skip padding / unknown chars

                buffer = (buffer << 5) | value;
                bitsLeft += 5;

                if (bitsLeft >= 8)
                {
                    bitsLeft -= 8;
                    output.Add((byte)((buffer >> bitsLeft) & 0xFF));
                }
            }

            return output.ToArray();
        }
    }
}
