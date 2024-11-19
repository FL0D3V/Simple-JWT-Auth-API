namespace Identity.Api.Dtos;


public struct RefreshTokenAndLoginClientTokenResponseDto
{
    public RefreshTokenAndLoginClientTokenResponseDto(string refreshToken, string loginClientToken)
    {
        RefreshToken = refreshToken;
        LoginClientToken = loginClientToken;
    }


    public string RefreshToken { get; set; }
    public string LoginClientToken { get; set; }
}
