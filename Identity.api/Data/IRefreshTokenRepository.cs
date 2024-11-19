using Identity.Api.Dtos;

namespace Identity.Api.Data
{
    public interface IRefreshTokenRepository
    {
        bool CheckIfTokenIsValid(string token);
        bool DeleteAllTokensOfUser(Guid? userId);
        bool DeleteRefreshToken(string token);
        RefreshTokenAndLoginClientTokenResponseDto? InsertNewToken(Guid? userId, string? clientId = null);
        string? GetRefreshToken(Guid? userId, string clientId);
        bool RevokeAllTokenFromUser(Guid? userId);
        bool RevokeToken(string token);
    }
}