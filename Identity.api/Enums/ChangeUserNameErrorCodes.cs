namespace Identity.Api.Enums;


public enum ChangeUserNameErrorCodes
{
    InvalidUserId,
    InvalidCredentials,
    NoUserFound,
    UserNameInUse,
    Success,
    OldAndNewUserNameMatch
}
