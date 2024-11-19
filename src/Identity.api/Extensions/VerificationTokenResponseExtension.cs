using Identity.Api.Dtos;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace Identity.Api.Extensions;


public static class VerificationTokenResponseExtension
{
    private const char DELIMITER = '&';



    public static string? EncodeToken(this VerificationTokenResponseDto? token)
    {
        if (token == null || !token.HasValue)
        {
            return null;
        }

        try
        {
            var finalTokenResponse = string.Concat(token.Value.Token, DELIMITER, token.Value.TokenType);
            var finalTokenBytes = Encoding.UTF8.GetBytes(finalTokenResponse);
            var finalToken = WebEncoders.Base64UrlEncode(finalTokenBytes);

            return finalToken;
        }
        catch
        {
            return null;
        }
    }


    public static VerificationTokenResponseDto? DecodeToken(this string? finalToken)
    {
        if (string.IsNullOrEmpty(finalToken))
        {
            return null;
        }

        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(finalToken);
            var decodedTokenData = Encoding.UTF8.GetString(decodedTokenBytes);
            var splittedData = decodedTokenData.Split(DELIMITER);

            if (splittedData.Length != 2)
            {
                return null;
            }

            var token = splittedData[0];
            var tokenType = splittedData[1];

            return new(token, tokenType);
        }
        catch
        {
            return null;
        }
    }
}