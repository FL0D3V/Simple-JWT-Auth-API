using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public class ForgotPasswordEmailDto
{
    [Required(ErrorMessage = "Email address is required")]
    [EmailAddress(ErrorMessage = "This is not a valid email address")]
    public string Email { get; set; }
}
