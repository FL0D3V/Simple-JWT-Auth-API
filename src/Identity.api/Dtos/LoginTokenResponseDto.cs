namespace Identity.Api.Dtos;


public class LoginTokenResponseDto
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }


    //// TODO: Try
    //public string Client { get; set; }
}
