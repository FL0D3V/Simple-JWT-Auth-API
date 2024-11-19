using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos;


public class PermissionRequestDto
{
    [Required]
    [RegularExpression(@"^[\w\-\:-[\r\n\s_]]+$")]
    public string Scope { get; set; }

    [Required]
    public string Description { get; set; }
}
