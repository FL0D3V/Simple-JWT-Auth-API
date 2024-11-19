using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public class ChangeEmailDto
{
    [Required]
    [EmailAddress(ErrorMessage = "This is not a valid email address")]
    public string NewEmail { get; set; }

    [Required]
    [Compare(nameof(NewEmail), ErrorMessage = "The emails do not match")]
    [EmailAddress]
    public string ConfirmNewEmail { get; set; }
}
