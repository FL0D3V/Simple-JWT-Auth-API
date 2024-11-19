namespace Identity.Api.Enums;


public enum ChangeEmailErrorCodes
{
    InvalidUserId,
    InvalidCredentials,
    NoUserFound,
    CouldNotCreateToken,
    EmailInUse,
    OldAndNewEmailMatch,
    Success,
    ValidTokenExistsAlready
}
