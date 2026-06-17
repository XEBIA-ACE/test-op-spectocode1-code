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
    /// Unit tests for <see cref="AuthController"/>.
    /// Covers the POST /api/auth/register endpoint across all acceptance-criteria branches:
    ///   1. Valid email  → 200 OK + IEmailSender called
    ///   2. Invalid email formats → 400 Bad Request with structured ErrorResponse
    ///   3. IEmailSender throws  → 500 Internal Server Error with structured ErrorResponse
    /// </summary>
    public class AuthControllerTests
    {
        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        /// <summary>
        /// Builds an <see cref="AuthController"/> with the supplied email-sender mock
        /// and minimal configuration stubs.
        /// </summary>
        private static AuthController BuildController(Mock<IEmailSender> emailSenderMock)
        {
            var configData = new Dictionary<string, string?>
            {
                ["Jwt:Key"]      = "test-secret-key-for-unit-tests-256-bits-long!!",
                ["Jwt:Issuer"]   = "TestIssuer",
                ["Jwt:Audience"] = "TestAudience"
            };

            IConfiguration configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configData)
                .Build();

            var logger = Mock.Of<ILogger<AuthController>>();

            return new AuthController(configuration, logger, emailSenderMock.Object);
        }

        // -----------------------------------------------------------------------
        // Happy-path tests
        // -----------------------------------------------------------------------

        [Fact]
        public async Task Register_ValidEmail_Returns200Ok()
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(StatusCodes.Status200OK, okResult.StatusCode);
        }

        [Fact]
        public async Task Register_ValidEmail_CallsIEmailSenderOnce()
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            await controller.Register(request);

            // Assert – IEmailSender must be invoked exactly once with the normalised address
            emailSenderMock.Verify(
                s => s.SendEmailAsync("user@example.com", It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task Register_ValidEmail_NormalisesAddressToLowercase()
        {
            // Arrange – submit mixed-case address; sender should receive lowercase
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "User.Name@Example.COM" };

            // Act
            var result = await controller.Register(request);

            // Assert
            Assert.IsType<OkObjectResult>(result);
            emailSenderMock.Verify(
                s => s.SendEmailAsync("user.name@example.com", It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task Register_ValidEmail_ResponseBodyContainsMessage()
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "valid@domain.org" };

            // Act
            var result = await controller.Register(request);

            // Assert – response body must carry a non-empty message (no enumeration signal)
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.NotNull(okResult.Value);

            // Use reflection to read the anonymous-type "message" property
            var messageProperty = okResult.Value!.GetType().GetProperty("message");
            Assert.NotNull(messageProperty);
            var messageValue = messageProperty!.GetValue(okResult.Value) as string;
            Assert.False(string.IsNullOrWhiteSpace(messageValue));
        }

        // -----------------------------------------------------------------------
        // Invalid-email tests  →  400 Bad Request
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("")]                        // empty string
        [InlineData("   ")]                     // whitespace only
        [InlineData("notanemail")]              // no @ symbol
        [InlineData("missing@")]               // no domain
        [InlineData("@nodomain.com")]          // no local part
        [InlineData("double@@domain.com")]     // double @
        [InlineData("spaces in@email.com")]    // space in local part
        [InlineData("plainaddress")]           // no @ at all
        [InlineData("missingdot@com")]         // single-label domain (no dot)
        public async Task Register_InvalidEmail_Returns400BadRequest(string invalidEmail)
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = invalidEmail };

            // Act
            var result = await controller.Register(request);

            // Assert
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
        }

        [Theory]
        [InlineData("")]
        [InlineData("notanemail")]
        [InlineData("missing@")]
        public async Task Register_InvalidEmail_ReturnsStructuredErrorResponse(string invalidEmail)
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = invalidEmail };

            // Act
            var result = await controller.Register(request);

            // Assert – body must be a structured ErrorResponse
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            var errorResponse = Assert.IsType<ErrorResponse>(badRequest.Value);
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Error));
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Message));
            Assert.Equal(400, errorResponse.StatusCode);
        }

        [Theory]
        [InlineData("")]
        [InlineData("bad-email")]
        public async Task Register_InvalidEmail_DoesNotCallIEmailSender(string invalidEmail)
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = invalidEmail };

            // Act
            await controller.Register(request);

            // Assert – email sender must never be invoked for invalid addresses
            emailSenderMock.Verify(
                s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Never);
        }

        [Fact]
        public async Task Register_NullRequest_Returns400BadRequest()
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            var controller = BuildController(emailSenderMock);

            // Act
            var result = await controller.Register(null!);

            // Assert
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
            var errorResponse = Assert.IsType<ErrorResponse>(badRequest.Value);
            Assert.Equal(400, errorResponse.StatusCode);
        }

        // -----------------------------------------------------------------------
        // Email-sender failure tests  →  500 Internal Server Error
        // -----------------------------------------------------------------------

        [Fact]
        public async Task Register_EmailSenderThrows_Returns500InternalServerError()
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new InvalidOperationException("SMTP server unavailable"));

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert
            var serverError = Assert.IsType<ObjectResult>(result);
            Assert.Equal(StatusCodes.Status500InternalServerError, serverError.StatusCode);
        }

        [Fact]
        public async Task Register_EmailSenderThrows_ReturnsStructuredErrorResponse()
        {
            // Arrange
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new Exception("Downstream mail service timed out"));

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert – body must be a structured ErrorResponse; must NOT leak exception details
            var serverError = Assert.IsType<ObjectResult>(result);
            var errorResponse = Assert.IsType<ErrorResponse>(serverError.Value);
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Error));
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Message));
            Assert.Equal(500, errorResponse.StatusCode);

            // Security: raw exception message must not be surfaced to the client
            Assert.DoesNotContain("timed out", errorResponse.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Register_EmailSenderThrows_IEmailSenderWasStillCalled()
        {
            // Arrange – verify the controller did attempt to call the sender before catching
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new InvalidOperationException("Connection refused"));

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            await controller.Register(request);

            // Assert
            emailSenderMock.Verify(
                s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task Register_EmailSenderThrowsTaskCanceledException_Returns500()
        {
            // Arrange – simulate a timeout scenario
            var emailSenderMock = new Mock<IEmailSender>();
            emailSenderMock
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new TaskCanceledException("Request timed out"));

            var controller = BuildController(emailSenderMock);
            var request = new RegisterEmailRequest { Email = "timeout@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert
            var serverError = Assert.IsType<ObjectResult>(result);
            Assert.Equal(StatusCodes.Status500InternalServerError, serverError.StatusCode);
            var errorResponse = Assert.IsType<ErrorResponse>(serverError.Value);
            Assert.Equal(500, errorResponse.StatusCode);
        }
    }
}
