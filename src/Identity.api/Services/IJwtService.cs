using Identity.Api.Dtos;
using System.Security.Claims;

namespace Identity.Api.Services
{
    public interface IJwtService
    {
        string GenerateJwtToken(UserClaimsDto? user);
        ClaimsPrincipal? GetPrincipalFromExpiredJwtToken(string jwtToken);
    }
}