using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using ApiGateway.Controllers;
using ApiGateway.Models;
using ApiGateway.Services;

namespace ApiGateway.Tests.Controllers
{
    /// <summary>
    /// Unit tests for <see cref="AuthController"/> covering the phone registration
    /// endpoint and SMS sending service integration.
    /// </summary>
    public class AuthControllerTests
    {
        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private static AuthController CreateController(
            ISmsService? smsService = null,
            IConfiguration? configuration = null)
        {
            configuration ??= BuildConfiguration();
            smsService ??= Mock.Of<ISmsService>();
            var logger = Mock.Of<ILogger<AuthController>>();
            return new AuthController(configuration, logger, smsService);
        }

        private static IConfiguration BuildConfiguration()
        {
            var inMemory = new Dictionary<string, string?>
            {
                ["Jwt:Key"]      = "test-secret-key-for-unit-tests-256-bits-long!!",
                ["Jwt:Issuer"]   = "ApiGateway",
                ["Jwt:Audience"] = "ApiGatewayUsers"
            };
            return new ConfigurationBuilder()
                .AddInMemoryCollection(inMemory)
                .Build();
        }

        // -----------------------------------------------------------------------
        // RegisterPhone – phone number format validation
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("+14155552671")]   // US number
        [InlineData("+447911123456")]  // UK number
        [InlineData("+61412345678")]   // AU number
        public async Task RegisterPhone_ValidE164Number_ReturnOkAndSendsSms(string phoneNumber)
        {
            // Arrange
            var smsMock = new Mock<ISmsService>();
            smsMock.Setup(s => s.SendSmsAsync(phoneNumber, It.IsAny<string>()))
                   .ReturnsAsync(true);

            var controller = CreateController(smsMock.Object);
            var request = new PhoneRegistrationRequest { PhoneNumber = phoneNumber };

            // Act
            var result = await controller.RegisterPhone(request);

            // Assert
            var ok = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(StatusCodes.Status200OK, ok.StatusCode);

            // SMS must have been sent exactly once to the supplied number.
            smsMock.Verify(s => s.SendSmsAsync(phoneNumber, It.IsAny<string>()), Times.Once);
        }

        [Theory]
        [InlineData("")]               // empty
        [InlineData("   ")]            // whitespace
        [InlineData("14155552671")]    // missing leading +
        [InlineData("+1")]             // too short
        [InlineData("not-a-number")]   // non-numeric
        [InlineData("+0123456789")]    // leading zero after +
        public async Task RegisterPhone_InvalidPhoneNumber_ReturnsBadRequest(string phoneNumber)
        {
            // Arrange
            var smsMock = new Mock<ISmsService>();
            var controller = CreateController(smsMock.Object);
            var request = new PhoneRegistrationRequest { PhoneNumber = phoneNumber };

            // Act
            var result = await controller.RegisterPhone(request);

            // Assert
            var bad = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, bad.StatusCode);

            var error = Assert.IsType<ErrorResponse>(bad.Value);
            Assert.Equal("InvalidPhoneNumber", error.Error);

            // SMS must NOT be sent for invalid numbers.
            smsMock.Verify(s => s.SendSmsAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task RegisterPhone_SmsServiceFails_Returns500()
        {
            // Arrange
            const string phoneNumber = "+14155552671";
            var smsMock = new Mock<ISmsService>();
            smsMock.Setup(s => s.SendSmsAsync(phoneNumber, It.IsAny<string>()))
                   .ReturnsAsync(false);   // simulate send failure

            var controller = CreateController(smsMock.Object);
            var request = new PhoneRegistrationRequest { PhoneNumber = phoneNumber };

            // Act
            var result = await controller.RegisterPhone(request);

            // Assert
            var serverError = Assert.IsType<ObjectResult>(result);
            Assert.Equal(StatusCodes.Status500InternalServerError, serverError.StatusCode);

            var error = Assert.IsType<ErrorResponse>(serverError.Value);
            Assert.Equal("SmsSendFailed", error.Error);
        }

        // -----------------------------------------------------------------------
        // GenerateToken – existing behaviour must remain intact
        // -----------------------------------------------------------------------

        [Fact]
        public void GenerateToken_ValidCredentials_ReturnsOkWithToken()
        {
            // Arrange
            var controller = CreateController();
            var request = new LoginRequest { Username = "testuser", Password = "testpass" };

            // Act
            var result = controller.GenerateToken(request);

            // Assert
            var ok = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(StatusCodes.Status200OK, ok.StatusCode);
            Assert.NotNull(ok.Value);
        }

        [Theory]
        [InlineData("", "password")]
        [InlineData("username", "")]
        [InlineData("", "")]
        public void GenerateToken_MissingCredentials_ReturnsBadRequest(string username, string password)
        {
            // Arrange
            var controller = CreateController();
            var request = new LoginRequest { Username = username, Password = password };

            // Act
            var result = controller.GenerateToken(request);

            // Assert
            var bad = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, bad.StatusCode);
        }
    }
}
