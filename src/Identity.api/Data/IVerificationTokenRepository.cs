using Identity.Api.Dtos;
using Identity.Api.Enums;

namespace Identity.Api.Data;


public interface IVerificationTokenRepository
{
    VerificationTokenResponseDto? InsertNewToken(Guid? userId, string tokenType, int expiresInHours, out VerificationTokenCheckErrorCodes errorCode);
    Guid? ConfirmValidTokenAndGetUserId(VerificationTokenResponseDto? token, out VerificationTokenCheckErrorCodes errorCode);
    VerificationTokenCheckErrorCodes CheckIfValidTokenIsConfirmed(Guid? userId, string tokenType);
    Guid? GetUserIdFromValidToken(VerificationTokenResponseDto? token, out VerificationTokenCheckErrorCodes errorCode);
    VerificationTokenCheckErrorCodes ConfirmValidTokenOnly(VerificationTokenResponseDto? token);
}