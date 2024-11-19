using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public struct VerificationTokenResponseDto
{
    public VerificationTokenResponseDto(string token, string tokenType)
    {
        Token = token;
        TokenType = tokenType;
    }


    [Required]
    public string Token { get; set; }

    [Required]
    public string TokenType { get; set; }
}