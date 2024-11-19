using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public class UserClaimsDto
{
    [Required]
    public Guid UserId { get; set; }

    [Required]
    public string UserName { get; set; }

    [Required]
    public string LanguageCode { get; set; }

    [Required]
    public List<string> Roles { get; set; } = new();

    [Required]
    public string LoginClientToken { get; set; }

    [Required]
    public DateTimeOffset CreatedDate { get; set; }
}
