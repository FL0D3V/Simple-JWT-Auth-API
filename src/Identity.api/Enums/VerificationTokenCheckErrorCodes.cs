namespace Identity.Api.Enums;


public enum VerificationTokenCheckErrorCodes
{
    InvalidUserId,
    InvalidTokenType,
    NoTokenFound,
    TokenExpired,
    TokenNotConfirmed,
    InvalidCredentials,
    Success,
    ValidTokenExistsAlready
}
