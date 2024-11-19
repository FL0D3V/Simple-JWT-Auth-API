using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public class ChangeUserNameDto
{
    [Required(ErrorMessage = "The username is required")]
    [RegularExpression(@"^[\w-[\r\n\v]]+$", ErrorMessage = "The username doesn't match our requirements")]
    [StringLength(maximumLength: 100, MinimumLength = 4, ErrorMessage = "Username must be between 4 and 100 characters")]
    public string UserName { get; set; }
}
