using Identity.Api.CustomAttributes;
using Identity.Api.Enums;
using System.ComponentModel.DataAnnotations;
using System.Globalization;

namespace Identity.Api.Dtos;


public class UserRegisterDto
{
    // FloDev_1
    // Dr. Dr. Ing.
    // Florian
    // Maier
    // de-AT
    // florian.maier@email.com
    // 2  ->  male
    // 123456
    // 123456


    [Required(ErrorMessage = "The username is required")]
    [RegularExpression(@"^[\w-[\r\n\v]]+$", ErrorMessage = "The username doesn't match our requirements")]
    [StringLength(maximumLength: 100, MinimumLength = 4, ErrorMessage = "Username must be between 4 and 100 characters")]
    public string UserName { get; set; }

    [RegularExpression(@"^[\w\.\s-[\d\r\n\v_]]+$", ErrorMessage = "The title doesn't match our requirements")]
    [MaxLength(50, ErrorMessage = "Title must be between 0 and 50 characters")]
    public string? Title { get; set; }

    [Required(ErrorMessage = "The first name is required")]
    [RegularExpression(@"^[\w-[\d\r\n\v_]]+$", ErrorMessage = "The first name doesn't match our requirements")]
    [StringLength(maximumLength: 100, MinimumLength = 1, ErrorMessage = "The first name must only be between 1 and 100")]
    public string FirstName { get; set; }

    [Required(ErrorMessage = "The last name is required")]
    [RegularExpression(@"^[\w-[\d\r\n\v_]]+$", ErrorMessage = "The last name doesn't match our requirements")]
    [StringLength(maximumLength: 100, MinimumLength = 1, ErrorMessage = "The last name must only be between 1 and 100")]
    public string LastName { get; set; }

    [Required(ErrorMessage = "The country code is required")]
    [LanguageCode(ErrorMessage = "Language code not found or not valid")]
    public string LanguageCode { get; set; }

    [Required(ErrorMessage = "Email address is required")]
    [EmailAddress(ErrorMessage = "This is not a valid email address")]
    public string Email { get; set; }

    [Required(ErrorMessage = "The Gender is required")]
    [EnumDataType(typeof(GenderCodes))]
    public GenderCodes Gender { get; set; } = GenderCodes.NotSet;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(maximumLength: 100, MinimumLength = 6, ErrorMessage = "Password must be between 6 and 100 characters")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Required(ErrorMessage = "Confirm password is required")]
    [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }
}
