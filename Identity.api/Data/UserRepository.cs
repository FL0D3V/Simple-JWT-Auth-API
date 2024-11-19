using Identity.Api.Dtos;
using Identity.Api.Enums;
using Identity.Api.Extensions;
using Identity.Api.Helper;
using Identity.Api.Models;
using Identity.Api.Services;

namespace Identity.Api.Data;


public class UserRepository : IUserRepository
{
    private readonly List<User> Users = new();

    private readonly ISecurePasswordService _securePasswordService;
    private readonly IRoleRepository _roleRepository;
    private readonly IConfiguration _configuration;
    private readonly IVerificationTokenRepository _verificationTokenRepository;


    public UserRepository(IVerificationTokenRepository verificationTokenRepository, ISecurePasswordService securePasswordService, IRoleRepository roleRepository, IConfiguration configuration)
    {
        _verificationTokenRepository = verificationTokenRepository;
        _securePasswordService = securePasswordService;
        _roleRepository = roleRepository;
        _configuration = configuration;

        InitTestUsers();
    }


    private void InitTestUsers()
    {
        Users.AddRange(new List<User>()
        {
            new User()
            {
                Id = Guid.NewGuid(),
                UserName = "FloDev",
                LastChangedUserNameDate = DateTimeOffset.UtcNow,
                Email = "florian.maier2002@gmail.com",
                NormalizedEmail = "florian.maier2002@gmail.com".ToNormalized(),
                EmailConfirmed = true,
                EmailConfirmedDate = DateTime.UtcNow,
                Password = _securePasswordService.HashPassword("123456", _securePasswordService.GetNewSalt(out var salt1)),
                PasswordSalt = salt1,
                LastChangedPasswordDate = DateTimeOffset.UtcNow,
                Roles = new()
                {
                    _roleRepository.GetRoleByName(RoleTypeHelper.InternalAdmin),
                },
                Title = "Ing.",
                FirstName = "Florian",
                LastName = "Maier",
                Gender = GenderCodes.Male,
                TwoFactorEnabled = false,
                LanguageCode = "de-AT",
                CreatedDate = DateTimeOffset.UtcNow,
                ModifiedDate = DateTimeOffset.UtcNow,
            },
            new User()
            {
                Id = Guid.NewGuid(),
                UserName = "LuLe",
                LastChangedUserNameDate = DateTimeOffset.UtcNow,
                Email = "lukas@leeb-bau.at",
                NormalizedEmail = "lukas@leeb-bau.at".ToNormalized(),
                EmailConfirmed = true,
                EmailConfirmedDate = DateTime.UtcNow,
                Password = _securePasswordService.HashPassword("123456", _securePasswordService.GetNewSalt(out var salt2)),
                PasswordSalt = salt2,
                LastChangedPasswordDate = DateTimeOffset.UtcNow,
                Roles = new()
                {
                    _roleRepository.GetRoleByName(RoleTypeHelper.OrganizationHead)
                },
                Title = "BSc.",
                FirstName = "Lukas",
                LastName = "Leeb",
                Gender = GenderCodes.Male,
                TwoFactorEnabled = false,
                LanguageCode = "en-EN",
                CreatedDate = DateTimeOffset.UtcNow,
                ModifiedDate = DateTimeOffset.UtcNow,
            },
        });
    }


    private UserClaimsDto? ConvertUserToUserClaimsDto(User? user, string? loginClientToken = null)
    {
        if (user == null)
            return null;

        UserClaimsDto? claimInfo = new()
        {
            UserId = user.Id,
            CreatedDate = user.CreatedDate,
            UserName = user.UserName,
            LanguageCode = user.LanguageCode,
            LoginClientToken = loginClientToken,
            Roles = user.Roles.Select(r => _roleRepository.GetRoleById(r.Id)?.Name).ToList(),
        };
        return claimInfo;
    }

    private UserInfoRequestDto? ConvertUserToUserInfoDto(User? user)
    {
        if (user == null)
            return null;

        var userInfo = new UserInfoRequestDto()
        {
            UserName = user.UserName,
            CreatedDate = user.CreatedDate,
            Email = user.Email,
            Roles = user.Roles.Select(r => _roleRepository.GetRoleById(r.Id)?.Name).ToList(),
            Gender = user.Gender,
            DisplayName = user.DisplayName(),
            PhoneNumber = user.PhoneNumber,
            LanguageCode = user.LanguageCode,
            LastModifiedDate = user.ModifiedDate,
        };
        return userInfo;
    }


    private void CompareLoginParams(User user, UserLoginDto dto, out LoginUserCheckErrorCodes code)
    {
        // Basic login checks to get the specific user!
        var basicCheck = user.NormalizedEmail == dto.Email.Trim().ToNormalized();

        if (!basicCheck)
        {
            code = LoginUserCheckErrorCodes.NotAUser;
            return;
        }

        // Password check to return faster!
        var passCheck = user.Password.SequenceEqual(_securePasswordService.HashPassword(dto.Password, user.PasswordSalt));

        if (!passCheck)
        {
            code = LoginUserCheckErrorCodes.WrongPassword;
            return;
        }

        // Only let verified and not locked out users login!
        var userIsVerifiedCheck = user.EmailConfirmed;


        if (!userIsVerifiedCheck)
        {
            code = LoginUserCheckErrorCodes.NotVerified;
            return;
        }
        
        // Don't let locked out users to login!
        var userIsLockedOutCheck = user.LockoutActive && user.LockoutEndDate >= DateTimeOffset.UtcNow;

        if (userIsLockedOutCheck)
        {
            code = LoginUserCheckErrorCodes.LockedOut;
            return;
        }

        // Every test passed!
        code = LoginUserCheckErrorCodes.Successfull;
    }


    public LoginCheckResponseDto CheckUserLogin(UserLoginDto? dto)
    {
        LoginUserCheckErrorCodes code = LoginUserCheckErrorCodes.NotAUser;

        if (dto == null)
        {
            return new(code, null);
        }

        var user = Users.FirstOrDefault(u =>
        {
            CompareLoginParams(u, dto, out var check);
            
            if (check == LoginUserCheckErrorCodes.NotAUser)
                return false;
            
            code = check;

            return true;
        });

        UserClaimsDto? userClaimDto = null;

        if (code == LoginUserCheckErrorCodes.Successfull)
        {
            userClaimDto = ConvertUserToUserClaimsDto(user);
        }

        return new(code, userClaimDto);
    }


    public UserInfoRequestDto? GetUserInfoFromUserId(Guid? userId)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return null;
        }

        return Users.Where(u => u.Id.Equals(userId) &&
                                u.EmailConfirmed &&
                                u.DeletedDate == null)
                    .Select(u => ConvertUserToUserInfoDto(u))
                    .FirstOrDefault();
    }


    public bool ChangeUserInfoFromUserId(Guid? userId, ChangeUserInfoDto? userInfo, out ChangeUserInfoErrorCodes errorCode)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            errorCode = ChangeUserInfoErrorCodes.InvalidUserId;
            return false;
        }

        if (userInfo == null)
        {
            errorCode = ChangeUserInfoErrorCodes.InvalidCredentials;
            return false;
        }

        var user = Users.FirstOrDefault(u => u.Id.Equals(userId) &&
                                             u.EmailConfirmed &&
                                             u.DeletedDate == null &&
                                             !u.LockoutActive); // && u.LockoutEndDate < DateTimeOffset.UtcNow

        if (user == null)
        {
            errorCode = ChangeUserInfoErrorCodes.NoUserFound;
            return false;
        }


        user.Title = userInfo.Title?.Trim();
        user.FirstName = userInfo.FirstName.Trim();
        user.LastName = userInfo.LastName.Trim();
        user.LanguageCode = userInfo.LanguageCode;
        user.Gender = userInfo.Gender;
        user.ProfilePicture = userInfo.ProfilePicture;

        errorCode = ChangeUserInfoErrorCodes.Success;

        return true;
    }


    public VerificationTokenResponseDto? ChangeEmailFromUserId(Guid? userId, ChangeEmailDto? changeEmail, out ChangeEmailErrorCodes errorCode)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            errorCode = ChangeEmailErrorCodes.InvalidUserId;
            return null;
        }

        if (changeEmail == null)
        {
            errorCode = ChangeEmailErrorCodes.InvalidCredentials;
            return null;
        }

        var user = Users.FirstOrDefault(u => u.Id.Equals(userId) &&
                                             u.EmailConfirmed &&
                                             u.DeletedDate == null &&
                                             !u.LockoutActive); // && u.LockoutEndDate < DateTimeOffset.UtcNow

        if (user == null)
        {
            errorCode = ChangeEmailErrorCodes.NoUserFound;
            return null;
        }


        var normEmail = changeEmail.NewEmail.Trim().ToNormalized();


        if (user.NormalizedEmail == normEmail)
        {
            errorCode = ChangeEmailErrorCodes.OldAndNewEmailMatch;
            return null;
        }


        // Check if email is already in use!
        if (Users.Any(t => t.NormalizedEmail == normEmail))
        {
            errorCode = ChangeEmailErrorCodes.EmailInUse;
            return null;
        }


        int expiresInHours = _configuration.GetValue<int>("VerificationToken:ExpiresInHours");


        // Inserts a new change-email-token with the given user id into the token store.
        var responseToken = _verificationTokenRepository.InsertNewToken(user.Id, VerificationTokenTypeHelper.VerifyEmail, expiresInHours, out var verificationErrorCode);


        switch (verificationErrorCode)
        {
            case VerificationTokenCheckErrorCodes.InvalidCredentials:
            case VerificationTokenCheckErrorCodes.InvalidTokenType:
                errorCode = ChangeEmailErrorCodes.InvalidCredentials;
                return null;

            case VerificationTokenCheckErrorCodes.ValidTokenExistsAlready:
                errorCode = ChangeEmailErrorCodes.ValidTokenExistsAlready;
                return null;

            case VerificationTokenCheckErrorCodes.Success:
                if (responseToken == null || !responseToken.HasValue)
                {
                    errorCode = ChangeEmailErrorCodes.CouldNotCreateToken;
                    return null;
                }

                user.Email = changeEmail.NewEmail.Trim();
                user.NormalizedEmail = normEmail;
                user.EmailConfirmed = false;
                user.EmailConfirmedDate = null;

                errorCode = ChangeEmailErrorCodes.Success;

                return responseToken;


            // Just for the compiler!
            default:
                errorCode = ChangeEmailErrorCodes.NoUserFound;
                return null;
        }
    }


    public bool ChangeUserNameFromUserId(Guid? userId, ChangeUserNameDto? changeUserName, out ChangeUserNameErrorCodes errorCode)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            errorCode = ChangeUserNameErrorCodes.InvalidUserId;
            return false;
        }

        if (changeUserName == null)
        {
            errorCode = ChangeUserNameErrorCodes.InvalidCredentials;
            return false;
        }

        var user = Users.FirstOrDefault(u => u.Id.Equals(userId) &&
                                             u.EmailConfirmed &&
                                             u.DeletedDate == null &&
                                             !u.LockoutActive); // && u.LockoutEndDate < DateTimeOffset.UtcNow

        if (user == null)
        {
            errorCode = ChangeUserNameErrorCodes.NoUserFound;
            return false;
        }


        var userName = changeUserName.UserName.Trim();

        // Check if old username and new matches
        if (user.UserName == userName)
        {
            errorCode = ChangeUserNameErrorCodes.OldAndNewUserNameMatch;
            return false;
        }

        // Check if username is already in use!
        if (Users.Any(t => t.UserName == userName))
        {
            errorCode = ChangeUserNameErrorCodes.UserNameInUse;
            return false;
        }


        user.UserName = userName;
        user.LastChangedUserNameDate = DateTimeOffset.UtcNow;

        errorCode = ChangeUserNameErrorCodes.Success;
        
        return true;
    }


    public UserClaimsDto? GetUserClaimsFromUserId(Guid? userId)
    {
        var user = Users.FirstOrDefault(u => u.Id.Equals(userId) &&
                                             u.EmailConfirmed &&
                                             u.DeletedDate == null &&
                                             !u.LockoutActive); // && u.LockoutEndDate < DateTimeOffset.UtcNow

        var userClaims = ConvertUserToUserClaimsDto(user);

        return userClaims;
    }


    private User? GenerateNewApplicationUser(UserRegisterDto user, List<Role> roles, out InsertNewUserErrorCodes errorCode)
    {
        var userName = user.UserName.Trim();
        var normEmail = user.Email.Trim().ToNormalized();


        // Check if username is already in use!
        if (Users.Any(t => t.UserName == userName))
        {
            errorCode = InsertNewUserErrorCodes.UserNameAlreadyExists;
            return null;
        }

        // Check email is already in use!
        if (Users.Any(t => t.NormalizedEmail == normEmail))
        {
            errorCode = InsertNewUserErrorCodes.EmailAlreadyExists;
            return null;
        }


        errorCode = InsertNewUserErrorCodes.Success;

        return new User()
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            LastChangedUserNameDate = DateTimeOffset.UtcNow,
            Email = user.Email.Trim(),
            NormalizedEmail = normEmail,
            EmailConfirmedDate = null,
            EmailConfirmed = false,
            Password = _securePasswordService.HashPassword(user.Password, _securePasswordService.GetNewSalt(out var salt)),
            PasswordSalt = salt,
            LastChangedPasswordDate = DateTimeOffset.UtcNow,
            Roles = roles, //roles.Select(r => r.Id).ToList(),
            Title = user.Title?.Trim(),
            FirstName = user.FirstName.Trim(),
            LastName = user.LastName.Trim(),
            LanguageCode = user.LanguageCode,
            Gender = user.Gender,
            TwoFactorEnabled = false,
            LockoutActive = false,
            LockoutEndDate = null,
            PhoneNumber = null,
            PhoneNumberConfirmed = false,
            PhoneNumberConfirmedDate = null,
            ProfilePicture = null,
            Signature = null,
            CreatedDate = DateTimeOffset.UtcNow,
            ModifiedDate = DateTimeOffset.UtcNow,
            DeletedDate = null
        };
    }


    public VerificationTokenResponseDto? InsertNewUser(UserRegisterDto? user, out InsertNewUserErrorCodes errorCode)
    {
        if (user == null)
        {
            errorCode = InsertNewUserErrorCodes.InvalidCredentials;
            return null;
        }


        var appUser = GenerateNewApplicationUser(user, new() { _roleRepository.GetRoleByName(RoleTypeHelper.OrganizationHead) ??
                                                       throw new Exception($"{nameof(RoleTypeHelper.OrganizationHead)} Role not found!"), },
                                                 out var genErrorCode);

        if (appUser == null)
        {
            errorCode = genErrorCode;
            return null;
        }


        int expiresInHours = _configuration.GetValue<int>("VerificationToken:ExpiresInHours");


        // Inserts a new register token with this new user id in the token store.
        var responseToken = _verificationTokenRepository.InsertNewToken(appUser.Id, VerificationTokenTypeHelper.VerifyEmail, expiresInHours, out var verificationErrorCode);


        switch (verificationErrorCode)
        {
            case VerificationTokenCheckErrorCodes.InvalidCredentials:
            case VerificationTokenCheckErrorCodes.InvalidTokenType:
                errorCode = InsertNewUserErrorCodes.InvalidCredentials;
                return null;

            case VerificationTokenCheckErrorCodes.ValidTokenExistsAlready:
                errorCode = InsertNewUserErrorCodes.ValidTokenExistsAlready;
                return null;

            case VerificationTokenCheckErrorCodes.Success:
                break;

            default:
                break;
        }

        if (responseToken == null || !responseToken.HasValue)
        {
            errorCode = InsertNewUserErrorCodes.CouldNotCreateVerificationToken;
            return null;
        }

        // Add the new user to the data store
        Users.Add(appUser);

        errorCode = InsertNewUserErrorCodes.Success;

        // Return the response token. This token should get send per email in the future!
        return responseToken;
    }


    public ConfirmEmailErrorCodes ConfirmEmailOfUser(VerificationTokenResponseDto? token)
    {
        Guid? userId = _verificationTokenRepository.ConfirmValidTokenAndGetUserId(token, out var errorCode);


        switch (errorCode)
        {
            case VerificationTokenCheckErrorCodes.InvalidCredentials:
                return ConfirmEmailErrorCodes.InvalidCredentials;

            case VerificationTokenCheckErrorCodes.NoTokenFound:
                return ConfirmEmailErrorCodes.VerificationTokenNotValid;

            case VerificationTokenCheckErrorCodes.TokenExpired:
                return ConfirmEmailErrorCodes.VerificationTokenExpired;

            case VerificationTokenCheckErrorCodes.Success:
                break;

            default:
                break;
        }


        if (userId == null || !userId.HasValue || userId == default)
        {
            return ConfirmEmailErrorCodes.VerificationTokenNotValid;
        }

        var user = Users.FirstOrDefault(u => u.Id.Equals(userId) &&
                                             u.DeletedDate == null);

        if (user == null)
        {
            return ConfirmEmailErrorCodes.UserNotFound;
        }


        user.EmailConfirmed = true;
        user.EmailConfirmedDate = DateTime.UtcNow;

        return ConfirmEmailErrorCodes.Success;
    }


    public VerificationTokenResponseDto? ForogotPassword(ForgotPasswordEmailDto emailDto, out ForgotPasswordErrorCodes errorCode)
    {
        if (emailDto == null)
        {
            errorCode = ForgotPasswordErrorCodes.InvalidCredentials;
            return null;
        }


        var normEmail = emailDto.Email.Trim().ToNormalized();


        // Try to find the given email in the system
        var user = Users.FirstOrDefault(u => u.NormalizedEmail == normEmail && // u.EmailConfirmed &&
                                             u.DeletedDate == null &&
                                             !u.LockoutActive); // && u.LockoutEndDate < DateTimeOffset.UtcNow

        if (user == null)
        {
            errorCode = ForgotPasswordErrorCodes.NoUserFound;
            return null;
        }

        if (!user.EmailConfirmed)
        {
            errorCode = ForgotPasswordErrorCodes.EmailNotConfirmed;
            return null;
        }

        int expiresInHours = _configuration.GetValue<int>("VerificationToken:ExpiresInHours");

        var responseToken = _verificationTokenRepository.InsertNewToken(user.Id, VerificationTokenTypeHelper.ChangePassword, expiresInHours, out var verificationErrorCode);


        switch (verificationErrorCode)
        {
            case VerificationTokenCheckErrorCodes.InvalidCredentials:
            case VerificationTokenCheckErrorCodes.InvalidTokenType:
                errorCode = ForgotPasswordErrorCodes.InvalidCredentials;
                return null;

            case VerificationTokenCheckErrorCodes.ValidTokenExistsAlready:
                errorCode = ForgotPasswordErrorCodes.ValidTokenExistsAlready;
                return null;

            case VerificationTokenCheckErrorCodes.Success:
                break;

            default:
                break;
        }

        // Only null when there is still a valid token in the system with this token type!
        if (responseToken == null)
        {
            errorCode = ForgotPasswordErrorCodes.CouldNotCreateVerificationToken;
            return null;
        }


        errorCode = ForgotPasswordErrorCodes.Success;

        return responseToken;
    }


    public bool CheckIfEmailOfUserIdIsVerified(Guid? userId)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return false;
        }

        var isConfirmed = Users.Where(u => u.Id.Equals(userId))
                               .Select(u => u.EmailConfirmed)
                               .FirstOrDefault();

        return isConfirmed;
    }


    public ChangePasswordErrorCodes ChangePassword(Guid? userId, string password)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return ChangePasswordErrorCodes.NotAValidUserId;
        }

        var user = Users.FirstOrDefault(u => u.Id.Equals(userId) &&
                                             u.EmailConfirmed &&
                                             u.DeletedDate == null &&
                                             !u.LockoutActive); // && u.LockoutEndDate < DateTimeOffset.UtcNow

        if (user == null)
        {
            return ChangePasswordErrorCodes.NoUserFound;
        }

        // Check if new password matches old password
        if (user.Password.SequenceEqual(_securePasswordService.HashPassword(password, user.PasswordSalt)))
        {
            return ChangePasswordErrorCodes.NewPasswordMatchesOld;
        }


        user.Password = _securePasswordService.HashPassword(password, _securePasswordService.GetNewSalt(out var salt));
        user.PasswordSalt = salt;
        user.LastChangedPasswordDate = DateTimeOffset.UtcNow;

        return ChangePasswordErrorCodes.Success;
    }


    public bool CheckIfPasswordIsCorrect(Guid? userId, string password)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            return false;
        }

        return Users.Any(u => u.Id.Equals(userId) &&
                              u.Password.SequenceEqual(_securePasswordService.HashPassword(password, u.PasswordSalt)));
    }
}