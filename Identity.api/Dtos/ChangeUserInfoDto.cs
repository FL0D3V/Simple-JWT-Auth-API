using Identity.Api.CustomAttributes;
using Identity.Api.Enums;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public class ChangeUserInfoDto
{
    [RegularExpression(@"^[\w\.\s-[\d\r\n\v_]]+$", ErrorMessage = "The title doesn't match our requirements")]
    [StringLength(maximumLength: 20, MinimumLength = 1, ErrorMessage = "Title must be between 1 and 20 characters")]
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

    [Required]
    [EnumDataType(typeof(GenderCodes))]
    public GenderCodes Gender { get; set; }

    public byte[]? ProfilePicture { get; set; } = null;
}
