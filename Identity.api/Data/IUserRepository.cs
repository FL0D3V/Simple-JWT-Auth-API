using Identity.Api.Dtos;
using Identity.Api.Enums;

namespace Identity.Api.Data;


public interface IUserRepository
{
    LoginCheckResponseDto CheckUserLogin(UserLoginDto dto);
    UserInfoRequestDto? GetUserInfoFromUserId(Guid? userId);
    ConfirmEmailErrorCodes ConfirmEmailOfUser(VerificationTokenResponseDto? token);
    public bool CheckIfEmailOfUserIdIsVerified(Guid? userId);
    public ChangePasswordErrorCodes ChangePassword(Guid? userId, string password);
    public bool CheckIfPasswordIsCorrect(Guid? userId, string password);
    UserClaimsDto? GetUserClaimsFromUserId(Guid? userId);
    bool ChangeUserInfoFromUserId(Guid? userId, ChangeUserInfoDto? userInfo, out ChangeUserInfoErrorCodes errorCode);
    bool ChangeUserNameFromUserId(Guid? userId, ChangeUserNameDto? changeUserName, out ChangeUserNameErrorCodes errorCode);
    VerificationTokenResponseDto? InsertNewUser(UserRegisterDto? user, out InsertNewUserErrorCodes errorCode);
    VerificationTokenResponseDto? ChangeEmailFromUserId(Guid? userId, ChangeEmailDto? changeEmail, out ChangeEmailErrorCodes errorCode);
    VerificationTokenResponseDto? ForogotPassword(ForgotPasswordEmailDto emailDto, out ForgotPasswordErrorCodes errorCodes);
}
