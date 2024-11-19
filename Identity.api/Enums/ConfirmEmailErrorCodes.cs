namespace Identity.Api.Enums;


public enum ConfirmEmailErrorCodes
{
    VerificationTokenNotValid,
    UserNotFound,
    Success,
    VerificationTokenExpired,
    InvalidCredentials,
}
