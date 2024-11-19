namespace Identity.Api.Enums;


public enum ForgotPasswordErrorCodes
{
    NoUserFound,
    InvalidCredentials,
    Success,
    CouldNotCreateVerificationToken,
    EmailNotConfirmed,
    ValidTokenExistsAlready
}
