using Identity.Api.Enums;

namespace Identity.Api.Dtos;


public struct LoginCheckResponseDto
{
    public LoginCheckResponseDto(LoginUserCheckErrorCodes code, UserClaimsDto? userDto)
    {
        ErrorCode = code;
        UserClaims = userDto;
    }


    public LoginUserCheckErrorCodes ErrorCode { get; set; } = LoginUserCheckErrorCodes.NotAUser;
    public UserClaimsDto? UserClaims { get; set; } = null;
}
