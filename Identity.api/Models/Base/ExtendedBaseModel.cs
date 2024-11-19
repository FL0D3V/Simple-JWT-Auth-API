using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models.Base;


public abstract class ExtendedBaseModel : BaseModel
{
    [Required]
    public DateTimeOffset ModifiedDate { get; set; } = DateTimeOffset.UtcNow;
}
