using Identity.Api.Data;
using Identity.Api.Dtos;
using Identity.Api.Dtos.Base;
using Identity.Api.Enums;
using Identity.Api.Extensions;
using Identity.Api.Helper;
using Identity.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers;


[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserRepository _userRepo;
    private readonly IJwtService _jwtService;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IVerificationTokenRepository _verificationTokenRepository;
    private readonly ILogger<UserController> _logger;


    public UserController(IUserRepository userRepo, IJwtService jwtService, IRefreshTokenRepository refreshTokenRepository,
                          IVerificationTokenRepository verificationTokenRepository, ILogger<UserController> logger)
    {
        _userRepo = userRepo;
        _jwtService = jwtService;
        _refreshTokenRepository = refreshTokenRepository;
        _verificationTokenRepository = verificationTokenRepository;
        _logger = logger;
    }



    [HttpPost("Login")]
    [AllowAnonymous]
    //[ValidateAntiForgeryToken]
    public ActionResult<LoginTokenResponseDto> Login([FromBody] UserLoginDto loginData)
    {
        // Check if user is already logged in
        if (JwtService.CheckIfAlreadyLoggedIn(User))
        {
            return BadRequest(new MessageResponseDto() { Message = "You are already logged in! Please logout first.", Code = (int)ResponseCodes.AlreadyLoggedIn });
        }

        // Check if the login data is null
        if (loginData == null)
        {
            return BadRequest(new MessageResponseDto() { Message = "Invalid Credentials!", Code = (int)ResponseCodes.InvalidCredentials });
        }


        // Check the login data (e.g. email and password)
        var userCheck = _userRepo.CheckUserLogin(loginData);

        switch (userCheck.ErrorCode)
        {
            case LoginUserCheckErrorCodes.NotAUser:
            case LoginUserCheckErrorCodes.WrongPassword:
                return BadRequest(new MessageResponseDto() { Message = "No User with the given credentials was found!", Code = (int)ResponseCodes.NoUserFound });

            case LoginUserCheckErrorCodes.NotVerified:
                return BadRequest(new MessageResponseDto() { Message = "You are not verified yet! Please go to your emails and click on the link that got send to you.", Code = (int)ResponseCodes.EmailNotConfirmed });

            case LoginUserCheckErrorCodes.LockedOut:
                return BadRequest(new MessageResponseDto() { Message = "You are currently locked out! Please check again later.", Code = (int)ResponseCodes.UserLockedOut });
        }


        // Generate a new refresh token for this user and this login attempt
        var refreshTokenAndLoginClientToken = _refreshTokenRepository.InsertNewToken(userCheck.UserClaims?.UserId);

        if (refreshTokenAndLoginClientToken == null || !refreshTokenAndLoginClientToken.HasValue)
        {
            return BadRequest(new MessageResponseDto() { Message = "Couldn't create your refresh token!", Code = (int)ResponseCodes.RefreshTokenError });
        }

        
        // Set the login client token to generate a valid jwt
        userCheck.UserClaims.LoginClientToken = refreshTokenAndLoginClientToken.Value.LoginClientToken;

        var jwt = _jwtService.GenerateJwtToken(userCheck.UserClaims);


        // Check if jwt is valid and return the jwt and the refresh token
        if (string.IsNullOrEmpty(jwt))
        {
            return BadRequest(new MessageResponseDto() { Message = "Couldn't create your login token!", Code = (int)ResponseCodes.CouldNotCreateJWT });
        }

        return Ok(new LoginTokenResponseDto() { Token = jwt, RefreshToken = refreshTokenAndLoginClientToken.Value.RefreshToken });
    }



    [HttpGet("UserInfo")]
    [Authorize]
    //[ValidateAntiForgeryToken]
    public ActionResult<UserInfoRequestDto> GetUserInfo()
    {
        Guid? userId = JwtService.GetUserIdFromPrincipal(User);
        
        var userInfo = _userRepo.GetUserInfoFromUserId(userId);

        if (userInfo == null)
        {
            return BadRequest(new MessageResponseDto() { Message = "No user with this id found or account is not verified!", Code = (int)ResponseCodes.InvalidUserId });
        }

        return Ok(userInfo);
    }



    [HttpPut("Change/UserInfo")]
    [Authorize]
    //[ValidateAntiForgeryToken]
    public IActionResult ChangeUserInfo([FromBody] ChangeUserInfoDto changeUserInfo)
    {
        Guid? userId = JwtService.GetUserIdFromPrincipal(User);

        var check = _userRepo.ChangeUserInfoFromUserId(userId, changeUserInfo, out var errorCode);


        switch (errorCode)
        {
            case ChangeUserInfoErrorCodes.InvalidUserId:
            case ChangeUserInfoErrorCodes.NoUserFound:
            case ChangeUserInfoErrorCodes.InvalidCredentials:
                return BadRequest(new MessageResponseDto() { Message = "There was an error while changing your user informations!", Code = (int)ResponseCodes.CouldNotChangeUserInfo });

            case ChangeUserInfoErrorCodes.Success:
                if (!check)
                {
                    return BadRequest(new MessageResponseDto() { Message = "Couldn't update your informations!", Code = (int)ResponseCodes.CouldNotChangeUserInfo });
                }

                return Ok(new MessageResponseDto() { Message = "Successfully updated your informations!", Code = (int)ResponseCodes.UserInfoChanged });


            // Just for the compiler!
            default:
                return BadRequest();
        }
    }


    [HttpPut("Change/Email")]
    [Authorize]
    //[ValidateAntiForgeryToken]
    public ActionResult<string> ChangeEmail([FromBody] ChangeEmailDto changeEmail)
    {
        Guid? userId = JwtService.GetUserIdFromPrincipal(User);

        var token = _userRepo.ChangeEmailFromUserId(userId, changeEmail, out var errorCode);

        switch (errorCode)
        {
            case ChangeEmailErrorCodes.InvalidUserId:
            case ChangeEmailErrorCodes.NoUserFound:
            case ChangeEmailErrorCodes.InvalidCredentials:
            case ChangeEmailErrorCodes.CouldNotCreateToken:
                return BadRequest(new MessageResponseDto() { Message = "There was an error while changing your email!", Code = (int)ResponseCodes.CouldNotChangeEmail });

            case ChangeEmailErrorCodes.OldAndNewEmailMatch:
                return BadRequest(new MessageResponseDto() { Message = "The old and new the new email matches!", Code = (int)ResponseCodes.OldAndNewEmailMatch });

            case ChangeEmailErrorCodes.EmailInUse:
                return BadRequest(new MessageResponseDto() { Message = "This email is already in use!", Code = (int)ResponseCodes.EmailAlreadyInUse });

            case ChangeEmailErrorCodes.ValidTokenExistsAlready:
                return BadRequest(new MessageResponseDto() { Message = "A change email call was already made! Please check your email and confirm your account!", Code = (int)ResponseCodes.VerificationTokenExistsAlready });

            case ChangeEmailErrorCodes.Success:
                if (token == null || !token.HasValue)
                {
                    return BadRequest(new MessageResponseDto() { Message = "There was an error while changing your email!", Code = (int)ResponseCodes.CouldNotChangeEmail });
                }

                // Encoding the token for simple web transfers.
                var finalToken = token.EncodeToken();

                // Check if encoded token is valid.
                if (string.IsNullOrEmpty(finalToken))
                {
                    return BadRequest(new MessageResponseDto() { Message = "There was an error while encoding your verification token!", Code = (int)ResponseCodes.VerificationTokenError });
                }

                // TODO: Send this token only to the given email!
                return Ok(finalToken);


            // Just for the compiler!
            default:
                return BadRequest();
        }
    }


    [HttpPut("Change/UserName")]
    [Authorize]
    //[ValidateAntiForgeryToken]
    public ActionResult<MessageResponseDto> ChangeUserName([FromBody] ChangeUserNameDto changeUserName)
    {
        Guid? userId = JwtService.GetUserIdFromPrincipal(User);

        var check = _userRepo.ChangeUserNameFromUserId(userId, changeUserName, out var errorCode);

        switch (errorCode)
        {
            case ChangeUserNameErrorCodes.InvalidUserId:
            case ChangeUserNameErrorCodes.NoUserFound:
            case ChangeUserNameErrorCodes.InvalidCredentials:
                return BadRequest(new MessageResponseDto() { Message = "There was an error while changing your username!", Code = (int)ResponseCodes.CouldNotChangeUserName });

            case ChangeUserNameErrorCodes.OldAndNewUserNameMatch:
                return BadRequest(new MessageResponseDto() { Message = "The old and new the new username matches!", Code = (int)ResponseCodes.OldAndNewUserNameMatch });

            case ChangeUserNameErrorCodes.UserNameInUse:
                return BadRequest(new MessageResponseDto() { Message = "This username is already in use!", Code = (int)ResponseCodes.UserNameAlreadyInUse });

            case ChangeUserNameErrorCodes.Success:
                if (!check)
                {
                    return BadRequest(new MessageResponseDto() { Message = "There was an error while changing your username!", Code = (int)ResponseCodes.CouldNotChangeUserName });
                }

                return Ok(new MessageResponseDto() { Message = "Successfully changed your username!", Code = (int)ResponseCodes.UserNameChanged });


            // Just for the compiler!
            default:
                return BadRequest();
        }
    }


    [HttpPost("Register")]
    [AllowAnonymous]
    //[ValidateAntiForgeryToken]
    public ActionResult<string> Register([FromBody] UserRegisterDto user)
    {
        if (JwtService.CheckIfAlreadyLoggedIn(User))
        {
            return BadRequest(new MessageResponseDto() { Message = "You are already logged in! Please logout first.", Code = (int)ResponseCodes.AlreadyLoggedIn });
        }


        var token = _userRepo.InsertNewUser(user, out var errorCode);


        switch (errorCode)
        {
            case InsertNewUserErrorCodes.InvalidCredentials:
                return BadRequest(new MessageResponseDto() { Message = "Invalid Credentials!", Code = (int)ResponseCodes.InvalidCredentials });

            case InsertNewUserErrorCodes.EmailAlreadyExists:
                return BadRequest(new MessageResponseDto() { Message = "This email already exists!", Code = (int)ResponseCodes.EmailAlreadyInUse });

            case InsertNewUserErrorCodes.UserNameAlreadyExists:
                return BadRequest(new MessageResponseDto() { Message = "This username already exists!", Code = (int)ResponseCodes.UserNameAlreadyInUse });

            case InsertNewUserErrorCodes.CouldNotCreateVerificationToken:
                return BadRequest(new MessageResponseDto() { Message = "There was an error while creating the verification token!", Code = (int)ResponseCodes.VerificationTokenError });

            case InsertNewUserErrorCodes.Success:
                var finalToken = token.EncodeToken();

                if (string.IsNullOrEmpty(finalToken))
                {
                    return BadRequest(new MessageResponseDto() { Message = "There was an error while encoding your verification token!", Code = (int)ResponseCodes.VerificationTokenError });
                }

                // TODO: Send this token only to the given email!
                return Ok(finalToken);


            // Just for the compiler!
            default:
                return BadRequest();
        }
    }


    [HttpGet("Verify")]
    [AllowAnonymous]
    //[ValidateAntiForgeryToken]
    public ActionResult<MessageResponseDto> VerifyEmail([FromQuery] string token)
    {
        VerificationTokenResponseDto? decodedToken = token.DecodeToken();

        if (decodedToken == null || !decodedToken.HasValue)
        {
            return BadRequest(new MessageResponseDto() { Message = "There was an error with the given token!", Code = (int)ResponseCodes.NotAValidVerificationToken });
        }


        if (decodedToken.Value.TokenType != VerificationTokenTypeHelper.VerifyEmail)
        {
            return BadRequest(new MessageResponseDto() { Message = "Wrong verification token type for this endpoint!", Code = (int)ResponseCodes.WrongVerificationTokenType });
        }


        var errorCode = _userRepo.ConfirmEmailOfUser(decodedToken);


        switch (errorCode)
        {
            case ConfirmEmailErrorCodes.InvalidCredentials:
                return BadRequest(new MessageResponseDto() { Message = "Invalid credentials!", Code = (int)ResponseCodes.InvalidCredentials });

            case ConfirmEmailErrorCodes.VerificationTokenNotValid:
                return BadRequest(new MessageResponseDto() { Message = "Invalid verification token!", Code = (int)ResponseCodes.VerificationTokenError });

            case ConfirmEmailErrorCodes.VerificationTokenExpired:
                return BadRequest(new MessageResponseDto() { Message = "Verification token expired! Please make a new request!", Code = (int)ResponseCodes.VerificationTokenExpired });

            case ConfirmEmailErrorCodes.UserNotFound:
                return BadRequest(new MessageResponseDto() { Message = "This user was not found!", Code = (int)ResponseCodes.NoUserFound });

            case ConfirmEmailErrorCodes.Success:
                return Ok(new MessageResponseDto() { Message = "Email confirmed!", Code = (int)ResponseCodes.EmailConfirmed });


            // Just for the compiler
            default:
                return BadRequest();
        }
    }



    [HttpPut("Change/Password")]
    [Authorize]
    //[ValidateAntiForgeryToken]
    public ActionResult<MessageResponseDto> ChangePasswordLoggedIn([FromBody] ChangePasswordDto newPassword)
    {
        var userId = JwtService.GetUserIdFromPrincipal(User);
        var actionResult = ChangePasswordBase(userId, newPassword, out _);

        return actionResult;
    }


    [HttpPost("ForgotPassword")]
    [AllowAnonymous]
    //[ValidateAntiForgeryToken]
    public ActionResult<string> ForgotPassword([FromBody] ForgotPasswordEmailDto emailDto)
    {
        if (JwtService.CheckIfAlreadyLoggedIn(User))
        {
            return BadRequest(new MessageResponseDto() { Message = "You are already logged in! Please logout first.", Code = (int)ResponseCodes.AlreadyLoggedIn });
        }

        var token = _userRepo.ForogotPassword(emailDto, out var errorCode);


        switch (errorCode)
        {
            case ForgotPasswordErrorCodes.InvalidCredentials:
                return BadRequest(new MessageResponseDto() { Message = "Invalid Credentials!", Code = (int)ResponseCodes.InvalidCredentials });

            case ForgotPasswordErrorCodes.NoUserFound:
                return BadRequest(new MessageResponseDto() { Message = "This user was not found!", Code = (int)ResponseCodes.NoUserFound });

            case ForgotPasswordErrorCodes.EmailNotConfirmed:
                return BadRequest(new MessageResponseDto() { Message = "This email is not verified yet!", Code = (int)ResponseCodes.EmailNotConfirmed });

            case ForgotPasswordErrorCodes.ValidTokenExistsAlready:
                return BadRequest(new MessageResponseDto() { Message = "A forgot password call was already made! Please check your email and change your password!", Code = (int)ResponseCodes.VerificationTokenExistsAlready });

            case ForgotPasswordErrorCodes.CouldNotCreateVerificationToken:
                return BadRequest(new MessageResponseDto() { Message = "Couldn't create the token!", Code = (int)ResponseCodes.VerificationTokenError });

            case ForgotPasswordErrorCodes.Success:
                var finalToken = token.EncodeToken();

                if (string.IsNullOrEmpty(finalToken))
                {
                    return BadRequest(new MessageResponseDto() { Message = "There was an error while encoding your verification token!", Code = (int)ResponseCodes.VerificationTokenError });
                }

                // TODO: Send this token only to the given email!
                return Ok(finalToken);


            // Just for the compiler
            default:
                return BadRequest();
        }
    }


    [HttpPut("Change/Password/Token")]
    [AllowAnonymous]
    //[ValidateAntiForgeryToken]
    public ActionResult<MessageResponseDto> ChangePasswordWithToken([FromQuery] string token, [FromBody] ForgotPasswordDto newPassword)
    {
        if (JwtService.CheckIfAlreadyLoggedIn(User))
        {
            return BadRequest(new MessageResponseDto() { Message = "You are already logged in! Please logout first.", Code = (int)ResponseCodes.AlreadyLoggedIn });
        }


        VerificationTokenResponseDto? decodedToken = token.DecodeToken();

        if (decodedToken == null || !decodedToken.HasValue)
        {
            return BadRequest(new MessageResponseDto() { Message = "There was an error with the given token!", Code = (int)ResponseCodes.NotAValidVerificationToken });
        }


        if (decodedToken.Value.TokenType != VerificationTokenTypeHelper.ChangePassword)
        {
            return BadRequest(new MessageResponseDto() { Message = "Wrong verification token type for this endpoint!", Code = (int)ResponseCodes.WrongVerificationTokenType });
        }



        var userId = _verificationTokenRepository.GetUserIdFromValidToken(decodedToken, out var errorCode);
        
        switch (errorCode)
        {
            case VerificationTokenCheckErrorCodes.InvalidCredentials:
                return BadRequest(new MessageResponseDto() { Message = "Invalid credentials!", Code = (int)ResponseCodes.InvalidCredentials });

            case VerificationTokenCheckErrorCodes.NoTokenFound:
                return BadRequest(new MessageResponseDto() { Message = "Invalid verification token!", Code = (int)ResponseCodes.VerificationTokenError });

            case VerificationTokenCheckErrorCodes.TokenExpired:
                return BadRequest(new MessageResponseDto() { Message = "Verification token expired! Please make a new request!", Code = (int)ResponseCodes.VerificationTokenExpired });

            case VerificationTokenCheckErrorCodes.Success:
                break;

            default:
                break;
        }


        var actionResult = ChangePasswordBase(userId, newPassword, out bool error);


        // No error happend, confirming token
        if (!error)
        {
            var checkCode = _verificationTokenRepository.ConfirmValidTokenOnly(decodedToken);

            switch (checkCode)
            {
                case VerificationTokenCheckErrorCodes.Success:
                    break;

                default:
                    return BadRequest(new MessageResponseDto() { Message = "Couldn't change your password because the token was invalid!", Code = (int)ResponseCodes.VerificationTokenError });
            }
        }

        return actionResult;
    }


    [HttpPost("RefreshToken")]
    [AllowAnonymous]
    //[ValidateAntiForgeryToken]
    public ActionResult<LoginTokenResponseDto> Refresh(LoginTokenResponseDto tokens)
    {
        // Get the claims principal from the old jwt
        var principal = _jwtService.GetPrincipalFromExpiredJwtToken(tokens.Token);
        
        if (principal == null)
        {
            return BadRequest(new MessageResponseDto() { Message = "Invalid login token!", Code = (int)ResponseCodes.InvalidJwt });
        }


        // Get the user id from the old jwt
        var userId = JwtService.GetUserIdFromPrincipal(principal);

        if (userId == null || !userId.HasValue || userId == default)
        {
            return BadRequest(new MessageResponseDto() { Message = "No user with this id found!", Code = (int)ResponseCodes.InvalidUserId });
        }


        // Get the login client token from the old jwt
        var loginClientToken = JwtService.GetLoginClientTokenFromPrincipal(principal);

        if (loginClientToken == null)
        {
            return BadRequest(new MessageResponseDto() { Message = "Invalid login token!", Code = (int)ResponseCodes.InvalidJwt });
        }
        

        // Retrieve the refresh token from the data store
        var savedRefreshToken = _refreshTokenRepository.GetRefreshToken(userId, loginClientToken);

        if (savedRefreshToken != tokens.RefreshToken)
        {
            return BadRequest(new MessageResponseDto() { Message = "Invalid refresh token!", Code = (int)ResponseCodes.InvalidRefreshToken });
        }


        // Generate a new user claims object from the user id of the jwt
        var userClaim = _userRepo.GetUserClaimsFromUserId(userId);

        if (userClaim == null)
        {
            return BadRequest(new MessageResponseDto() { Message = "Couldn't generate claims with this user id!", Code = (int)ResponseCodes.RefreshTokenError });
        }

        
        // Finaly delete the old refresh token
        var check = _refreshTokenRepository.DeleteRefreshToken(tokens.RefreshToken);

        if (!check)
        {
            return BadRequest(new MessageResponseDto() { Message = "Couldn't delete your old refresh token!", Code = (int)ResponseCodes.RefreshTokenError });
        }


        // Get 
        var refreshTokenAndClientId = _refreshTokenRepository.InsertNewToken(userId, loginClientToken);

        if (refreshTokenAndClientId == null)
        {
            return BadRequest(new MessageResponseDto() { Message = "Couldn't create your refresh token!", Code = (int)ResponseCodes.RefreshTokenError });
        }

        // Set the client id for a unique user login.
        userClaim.LoginClientToken = refreshTokenAndClientId.Value.LoginClientToken;

        // Generate the new jwt after checking if the old data was valid.
        var jwt = _jwtService.GenerateJwtToken(userClaim);


        if (string.IsNullOrEmpty(jwt))
        {
            return BadRequest(new MessageResponseDto() { Message = "Couldn't create your login token!", Code = (int)ResponseCodes.CouldNotCreateJWT });
        }

        return Ok(new LoginTokenResponseDto() { Token = jwt, RefreshToken = refreshTokenAndClientId.Value.RefreshToken });
    }



    private ActionResult<MessageResponseDto> ChangePasswordBase(Guid? userId, ChangePasswordDtoBase passwords, out bool error)
    {
        if (userId == null || !userId.HasValue || userId == default)
        {
            error = true;
            return BadRequest(new MessageResponseDto() { Message = "No user with this id found!", Code = (int)ResponseCodes.InvalidUserId });
        }

        if (passwords == null)
        {
            error = true;
            return BadRequest(new MessageResponseDto() { Message = "Invalid Credentials!", Code = (int)ResponseCodes.InvalidCredentials });
        }


        // Check if the given old password matches the intenal old password of this user.
        if (passwords is ChangePasswordDto complete)
        {
            var passwordCheck = _userRepo.CheckIfPasswordIsCorrect(userId, complete.OldPassword);

            if (!passwordCheck)
            {
                error = true;
                return BadRequest(new MessageResponseDto() { Message = "The old password is wrong!", Code = (int)ResponseCodes.WrongOldPasswordEntered });
            }
        }


        if (passwords.NewPassword != passwords.ConfirmNewPassword)
        {
            error = true;
            return BadRequest(new MessageResponseDto() { Message = "The new passwords do not match!", Code = (int)ResponseCodes.NewPasswordsDoNotMatch });
        }


        var changePasswordCheck = _userRepo.ChangePassword(userId, passwords.NewPassword);

        switch (changePasswordCheck)
        {
            case ChangePasswordErrorCodes.NotAValidUserId:
            case ChangePasswordErrorCodes.NoUserFound:
                error = true;
                return BadRequest(new MessageResponseDto() { Message = "There was an error while changing the password!", Code = (int)ResponseCodes.CouldNotChangePassword });
                
            case ChangePasswordErrorCodes.NewPasswordMatchesOld:
                error = true;
                return BadRequest(new MessageResponseDto() { Message = "The new password matches the old!", Code = (int)ResponseCodes.OldAndNewPasswordMatch });

            case ChangePasswordErrorCodes.Success:
                error = false;
                return Ok(new MessageResponseDto() { Message = "Password successfully changed!", Code = (int)ResponseCodes.PasswordChanged });


            // Just there to not throw errors!
            default:
                error = true;
                return BadRequest();
        }
    }
}
