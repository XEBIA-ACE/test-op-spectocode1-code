namespace ApiGateway.Services
{
    /// <summary>
    /// Abstraction for sending SMS messages.
    /// Decoupled from the concrete provider so the controller stays testable.
    /// </summary>
    public interface ISmsService
    {
        /// <summary>
        /// Sends a verification SMS to the supplied phone number.
        /// </summary>
        /// <param name="phoneNumber">E.164-formatted phone number, e.g. +14155552671</param>
        /// <param name="token">One-time verification token to include in the message body.</param>
        /// <returns>True when the message was accepted by the provider; false otherwise.</returns>
        Task<bool> SendVerificationSmsAsync(string phoneNumber, string token);
    }
}
