using Identity.Api.Dtos;
using Identity.Api.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Identity.Api.Services;


public class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;


    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
    }


    private static IEnumerable<Claim> GenerateClaims(UserClaimsDto user)
    {
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToUnixTime().ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new Claim(ClaimTypes.Locality, user.LanguageCode),
            new Claim(ClaimTypes.UserData, user.LoginClientToken),
        };

        foreach (var role in user.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        return claims;
    }


    public string GenerateJwtToken(UserClaimsDto? user)
    {
        if (user == null)
        {
            throw new ArgumentNullException("The user must not be null!");
        }

        if (string.IsNullOrEmpty(user.LoginClientToken))
        {
            throw new ArgumentNullException("The login client token must be set to generate a jwt!");
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

        var signIn = new SigningCredentials(key, GetValidAlgorithm());

        var token = new JwtSecurityToken(issuer: _configuration["Jwt:Issuer"],
                                         audience: _configuration["Jwt:Audience"],
                                         claims: GenerateClaims(user),
                                         notBefore: DateTime.UtcNow,
                                         expires: DateTime.UtcNow.AddMinutes(_configuration.GetValue<int>("Jwt:ExpiresInMinues")),
                                         signingCredentials: signIn);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }


    public ClaimsPrincipal? GetPrincipalFromExpiredJwtToken(string jwtToken)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = _configuration["Jwt:Audience"],
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateLifetime = false,           // We want to validate an expired jwt. So this parameter is false!
            ClockSkew = TimeSpan.Zero,
            ValidAlgorithms = GetValidAlgorithms()
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        try
        {
            var principal = tokenHandler.ValidateToken(jwtToken, tokenValidationParameters, out SecurityToken securityToken);

            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null) //  || !jwtSecurityToken.Header.Alg.Equals(GetValidAlgorithm(), StringComparison.InvariantCultureIgnoreCase)
            {
                return null;
            }
            
            return principal;
        }
        catch
        {
            return null;
        }
    }


    public static List<string> GetValidAlgorithms()
    {
        return new() { GetValidAlgorithm() };
    }

    public static string GetValidAlgorithm()
    {
        return SecurityAlgorithms.HmacSha512;
    }

    public static Guid? GetUserIdFromPrincipal(ClaimsPrincipal user)
    {
        string guid = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        return Guid.Parse(guid);
    }

    public static string? GetLoginClientTokenFromPrincipal(ClaimsPrincipal user)
    {
        var clientId = user.FindFirst(ClaimTypes.UserData)?.Value;
        return clientId;
    }

    public static bool CheckIfAlreadyLoggedIn(ClaimsPrincipal user)
    {
        return user.Identity?.IsAuthenticated ?? false;
    }
}


public static class JwtServiceExtension
{
    public static IServiceCollection AddJwtService(this IServiceCollection services)
    {
        return services.AddSingleton<IJwtService, JwtService>();
    }
}