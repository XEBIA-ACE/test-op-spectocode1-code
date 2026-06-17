using System.ComponentModel.DataAnnotations;

namespace ApiGateway.Models
{
    /// <summary>
    /// Request payload for phone number registration.
    /// </summary>
    public class PhoneRegistrationRequest
    {
        /// <summary>
        /// Phone number in E.164 format, e.g. +14155552671.
        /// </summary>
        [Required(ErrorMessage = "PhoneNumber is required.")]
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
