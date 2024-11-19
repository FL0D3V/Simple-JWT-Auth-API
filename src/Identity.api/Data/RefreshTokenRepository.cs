using Identity.Api.Dtos;
using Identity.Api.Helper;
using Identity.Api.Models;

namespace Identity.Api.Data;


public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly List<RefreshToken> RefreshTokens = new();

    private readonly IConfiguration _configuration;
    

    public RefreshTokenRepository(IConfiguration configuration)
    {
        _configuration = configuration;
    }



    public RefreshTokenAndLoginClientTokenResponseDto? InsertNewToken(Guid? userId, string? loginClientToken = null)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return null;
        }

        if (loginClientToken != null)
        {
            var check = RefreshTokens.Any(t => t.UserId.Equals(userId) &&
                                               t.LoginClientToken == loginClientToken &&
                                               t.ExpiresAt >= DateTimeOffset.UtcNow &&
                                               t.DeletedDate == null &&
                                               !t.Revoked);

            // Check if a refresh token with the given user id and login client token is still valid in the store
            if (check)
            {
                return null;
            }
        }


        loginClientToken ??= TokenHelper.GenerateClientLoginToken();

        var refreshToken = TokenHelper.GenerateRefreshToken();


        var tokenStorage = new RefreshToken()
        {
            Id = Guid.NewGuid(),
            UserId = userId.Value,
            Token = refreshToken,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_configuration.GetValue<int>("RefreshToken:ExpiresInDays")),
            LoginClientToken = loginClientToken,
            Revoked = false,
            RevokedAt = null,
            CreatedDate = DateTimeOffset.UtcNow,
            DeletedDate = null,
        };


        RefreshTokens.Add(tokenStorage);

        return new(refreshToken, loginClientToken);
    }


    public string? GetRefreshToken(Guid? userId, string clientId)
    {
        if (userId == null || !userId.HasValue || userId == default || string.IsNullOrEmpty(clientId))
        {
            return null;
        }

        var tokenStorage = RefreshTokens.FirstOrDefault(t => t.UserId.Equals(userId) &&                 // Matches the given user id
                                                             t.LoginClientToken == clientId &&          // Matches the client login token to uniquely identify the login
                                                             t.ExpiresAt > DateTimeOffset.UtcNow &&     // Not expired
                                                             t.DeletedDate == null &&                   // Not deleted
                                                             !t.Revoked);                               // Not revoked

        if (tokenStorage == null)
        {
            return null;
        }

        return tokenStorage.Token;
    }


    public bool CheckIfTokenIsValid(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        var check = RefreshTokens.Any(t => t.Token == token &&
                                           t.ExpiresAt > DateTimeOffset.UtcNow &&
                                           !t.Revoked &&
                                           t.DeletedDate == null);

        return check;
    }


    public bool RevokeToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        var tokenStorage = RefreshTokens.FirstOrDefault(t => t.Token == token &&
                                                             t.ExpiresAt > DateTimeOffset.UtcNow &&
                                                             !t.Revoked &&
                                                             t.DeletedDate == null);

        if (tokenStorage == null)
        {
            return false;
        }

        tokenStorage.Revoked = true;
        tokenStorage.RevokedAt = DateTimeOffset.UtcNow;

        return true;
    }


    public bool RevokeAllTokenFromUser(Guid? userId)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return false;
        }

        var tokenStorage = RefreshTokens.Where(t => t.UserId.Equals(userId) &&
                                                    t.ExpiresAt > DateTimeOffset.UtcNow &&
                                                    !t.Revoked &&
                                                    t.DeletedDate == null);

        if (tokenStorage == null)
        {
            return false;
        }

        foreach (var token in tokenStorage)
        {
            token.Revoked = true;
            token.RevokedAt = DateTimeOffset.UtcNow;
        }

        return true;
    }


    public bool DeleteRefreshToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        var tokenStorage = RefreshTokens.FirstOrDefault(t => t.Token == token &&
                                                             t.ExpiresAt > DateTimeOffset.UtcNow &&
                                                             !t.Revoked &&
                                                             t.DeletedDate == null);

        if (tokenStorage == null)
        {
            return false;
        }

        tokenStorage.DeletedDate = DateTimeOffset.UtcNow;

        return true;
    }


    public bool DeleteAllTokensOfUser(Guid? userId)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return false;
        }

        var tokenStorage = RefreshTokens.Where(t => t.UserId.Equals(userId) && !t.Revoked && t.DeletedDate != null);

        if (tokenStorage == null)
        {
            return true;
        }

        foreach (var token in tokenStorage)
        {
            token.DeletedDate = DateTimeOffset.UtcNow;
        }

        return true;
    }
}
