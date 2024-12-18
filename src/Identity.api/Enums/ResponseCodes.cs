﻿namespace Identity.Api.Enums;


public enum ResponseCodes
{
    NoUserFound,
    InvalidCredentials,
    AlreadyLoggedIn,
    InvalidUserId,
    EmailConfirmed,
    CouldNotConfirmEmail,
    WrongOldPasswordEntered,
    OldAndNewPasswordMatch,
    NewPasswordsDoNotMatch,
    CouldNotChangePassword,
    PasswordChanged,
    RefreshTokenError,
    InvalidJwt,
    EmailNotConfirmed,
    UserLockedOut,
    CouldNotCreateJWT,
    InvalidRefreshToken,
    CouldNotChangeUserInfo,
    UserInfoChanged,
    CouldNotChangeEmail,
    UserNameChanged,
    CouldNotChangeUserName,
    WrongVerificationTokenType,
    NotAValidVerificationToken,
    VerificationTokenError,
    OldAndNewEmailMatch,
    EmailAlreadyInUse,
    OldAndNewUserNameMatch,
    UserNameAlreadyInUse,
    VerificationTokenExpired,
    VerificationTokenExistsAlready,
}
