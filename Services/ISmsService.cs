namespace ApiGateway.Services
{
    /// <summary>
    /// Abstraction for sending SMS messages.
    /// Allows the SMS provider to be swapped or mocked in tests.
    /// </summary>
    public interface ISmsService
    {
        /// <summary>
        /// Sends an SMS message to the specified phone number.
        /// </summary>
        /// <param name="toPhoneNumber">Destination phone number in E.164 format (e.g. +14155552671).</param>
        /// <param name="message">Text body of the SMS.</param>
        /// <returns>True if the message was dispatched successfully; otherwise false.</returns>
        Task<bool> SendSmsAsync(string toPhoneNumber, string message);
    }
}
