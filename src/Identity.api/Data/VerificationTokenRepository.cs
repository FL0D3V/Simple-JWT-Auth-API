using Identity.Api.Dtos;
using Identity.Api.Enums;
using Identity.Api.Helper;
using Identity.Api.Models;

namespace Identity.Api.Data;


public class VerificationTokenRepository : IVerificationTokenRepository
{
    private readonly List<VerificationToken> Tokens = new();


    public VerificationTokenRepository()
    {
    }


    /// <summary>
    /// Inserts a new token with a user id and a token type.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tokenType">The token type.</param>
    /// <returns>The generated verification token.</returns>
    public VerificationTokenResponseDto? InsertNewToken(Guid? userId, string tokenType, int expiresInHours, out VerificationTokenCheckErrorCodes errorCode)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            errorCode = VerificationTokenCheckErrorCodes.InvalidCredentials;
            return null;
        }

        if (string.IsNullOrEmpty(tokenType))
        {
            errorCode = VerificationTokenCheckErrorCodes.InvalidTokenType;
            return null;
        }

        if (expiresInHours <= 0)
        {
            throw new ArgumentException($"\"{nameof(expiresInHours)}\" must be greater 0!");
        }

        var check = Tokens.Any(t => t.UserId.Equals(userId) &&
                                    t.TypeOfToken == tokenType &&
                                    t.DeletedDate == null &&
                                    t.ExpiresAt >= DateTimeOffset.UtcNow &&
                                    !t.IsConfirmed);

        // Check if the given token type already exists for this user
        if (check)
        {
            errorCode = VerificationTokenCheckErrorCodes.ValidTokenExistsAlready;
            return null;
        }

        // Generate a new verification token
        var generatedVerificationToken = TokenHelper.GenerateVerificationToken();

        var tokenStorage = new VerificationToken()
        {
            Id = Guid.NewGuid(),
            Token = generatedVerificationToken,
            UserId = userId.Value,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(expiresInHours),
            TypeOfToken = tokenType,
            IsConfirmed = false,
            ConfirmedDate = null,
            CreatedDate = DateTime.UtcNow,
            DeletedDate = null,
        };

        Tokens.Add(tokenStorage);


        errorCode = VerificationTokenCheckErrorCodes.Success;

        return new(generatedVerificationToken, tokenType);
    }



    /// <summary>
    /// Checks if a token of a user and with the given token type is confirmed.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tokenType">The token type.</param>
    /// <returns>The error code.</returns>
    public VerificationTokenCheckErrorCodes CheckIfValidTokenIsConfirmed(Guid? userId, string tokenType)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return VerificationTokenCheckErrorCodes.InvalidUserId;
        }

        if (string.IsNullOrEmpty(tokenType))
        {
            return VerificationTokenCheckErrorCodes.InvalidTokenType;
        }

        var tokenStorage = Tokens.FirstOrDefault(t => t.UserId.Equals(userId) &&
                                                      t.TypeOfToken == tokenType && // && t.IsConfirmed
                                                      t.DeletedDate == null); // && t.ExpiresAt >= DateTimeOffset.UtcNow

        if (tokenStorage == null)
        {
            return VerificationTokenCheckErrorCodes.NoTokenFound;
        }

        if (tokenStorage.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return VerificationTokenCheckErrorCodes.TokenExpired;
        }

        if (!tokenStorage.IsConfirmed)
        {
            return VerificationTokenCheckErrorCodes.TokenNotConfirmed;
        }


        return VerificationTokenCheckErrorCodes.Success;
    }


    /// <summary>
    /// Used to get the stored user id from the given token.
    /// </summary>
    /// <param name="token">The token data</param>
    /// <returns>The user id If a token with the given parameters was found else null.</returns>
    public Guid? GetUserIdFromValidToken(VerificationTokenResponseDto? token, out VerificationTokenCheckErrorCodes errorCode)
    {
        if (token == null || !token.HasValue)
        {
            errorCode = VerificationTokenCheckErrorCodes.InvalidCredentials;
            return null;
        }

        var tokenStorage = Tokens.FirstOrDefault(t => t.Token == token.Value.Token &&
                                                      t.TypeOfToken == token.Value.TokenType &&
                                                      !t.IsConfirmed &&
                                                      t.DeletedDate == null); // && t.ExpiresAt >= DateTimeOffset.UtcNow

        if (tokenStorage == null)
        {
            errorCode = VerificationTokenCheckErrorCodes.NoTokenFound;
            return null;
        }

        if (tokenStorage.ExpiresAt < DateTimeOffset.UtcNow)
        {
            errorCode = VerificationTokenCheckErrorCodes.TokenExpired;
            return null;
        }


        errorCode = VerificationTokenCheckErrorCodes.Success;

        return tokenStorage.UserId;
    }


    /// <summary>
    /// Used to confirm a token without getting the user id back.
    /// </summary>
    /// <param name="token">The token data</param>
    /// <returns>The error code.</returns>
    public VerificationTokenCheckErrorCodes ConfirmValidTokenOnly(VerificationTokenResponseDto? token)
    {
        if (token == null || !token.HasValue)
        {
            return VerificationTokenCheckErrorCodes.InvalidCredentials;
        }

        var tokenStorage = Tokens.FirstOrDefault(t => t.Token == token.Value.Token &&
                                                      t.TypeOfToken == token.Value.TokenType &&
                                                      !t.IsConfirmed &&
                                                      t.DeletedDate == null); // && t.ExpiresAt >= DateTimeOffset.UtcNow

        if (tokenStorage == null)
        {
            return VerificationTokenCheckErrorCodes.NoTokenFound;
        }

        if (tokenStorage.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return VerificationTokenCheckErrorCodes.TokenExpired;
        }


        tokenStorage.IsConfirmed = true;
        tokenStorage.ConfirmedDate = DateTimeOffset.UtcNow;
        tokenStorage.DeletedDate = DateTimeOffset.UtcNow;

        return VerificationTokenCheckErrorCodes.Success;
    }


    /// <summary>
    /// Used to confirm a not expired token.
    /// </summary>
    /// <param name="token">The token data</param>
    /// <returns>If everything worked, this function returns the user id connected to the given token.</returns>
    public Guid? ConfirmValidTokenAndGetUserId(VerificationTokenResponseDto? token, out VerificationTokenCheckErrorCodes errorCode)
    {
        if (token == null || !token.HasValue)
        {
            errorCode = VerificationTokenCheckErrorCodes.InvalidCredentials;
            return null;
        }

        var tokenStorage = Tokens.FirstOrDefault(t => t.Token == token.Value.Token &&
                                                      t.TypeOfToken == token.Value.TokenType &&
                                                      !t.IsConfirmed &&
                                                      t.DeletedDate == null); // && t.ExpiresAt >= DateTimeOffset.UtcNow

        if (tokenStorage == null)
        {
            errorCode = VerificationTokenCheckErrorCodes.NoTokenFound;
            return null;
        }

        if (tokenStorage.ExpiresAt < DateTimeOffset.UtcNow)
        {
            errorCode = VerificationTokenCheckErrorCodes.TokenExpired;
            return null;
        }


        tokenStorage.IsConfirmed = true;
        tokenStorage.ConfirmedDate = DateTimeOffset.UtcNow;
        tokenStorage.DeletedDate = DateTimeOffset.UtcNow;


        errorCode = VerificationTokenCheckErrorCodes.Success;

        return tokenStorage.UserId;
    }
}
