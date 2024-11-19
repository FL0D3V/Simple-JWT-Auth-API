using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace Identity.Api.Helper;


public static class TokenHelper
{
    private const int TOKEN_LEN = 64;
    private const int REFRESH_TOKEN_LEN = 64;
    private const int CLIENT_TOKEN_LEN = 15;


    public static string GenerateVerificationToken()
    {
        var bytes = new byte[TOKEN_LEN];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);

            return WebEncoders.Base64UrlEncode(bytes);
            //return Convert.ToHexString(tokenBytes).ToLower();
        }
    }


    public static string GenerateRefreshToken()
    {
        var bytes = new byte[REFRESH_TOKEN_LEN];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);

            return WebEncoders.Base64UrlEncode(bytes);
            //return Convert.ToHexString(bytes).ToLower();
        }
    }


    public static string GenerateClientLoginToken()
    {
        var bytes = new byte[CLIENT_TOKEN_LEN];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);

            return WebEncoders.Base64UrlEncode(bytes);
            //return Convert.ToHexString(bytes).ToLower();
        }
    }
}
