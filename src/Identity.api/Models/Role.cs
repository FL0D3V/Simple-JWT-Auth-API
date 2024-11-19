using Identity.Api.Models.Base;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class Role : ExtendedBaseModel
{
    [Required]
    [RegularExpression(@"^[\w\--[\r\n\s_]]+$")]
    public string Name { get; set; }

    [Required]
    public string Description { get; set; }
}