namespace Identity.Api.Enums;


public enum InsertNewUserErrorCodes
{
    InvalidCredentials,
    EmailAlreadyExists,
    UserNameAlreadyExists,
    CouldNotCreateVerificationToken,
    Success,
    ValidTokenExistsAlready
}
