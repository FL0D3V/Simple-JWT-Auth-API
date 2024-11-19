using Identity.Api.Models.Base;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class Permission : ExtendedBaseModel
{
    // e.g. user:read, user.info:write

    [Required]
    [RegularExpression(@"^[\w\.\:-[\r\n\s_]]+$")]
    public string Scope { get; set; }

    [Required]
    public string Description { get; set; }
}
