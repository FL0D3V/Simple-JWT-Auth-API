namespace Identity.Api.Enums;


public enum ChangePasswordErrorCodes
{
    Success,
    NotAValidUserId,
    NoUserFound,
    NewPasswordMatchesOld
}
