using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models.Base;


public abstract class BaseModel
{
    [Key]
    [Required]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public DateTimeOffset CreatedDate { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? DeletedDate { get; set; } = null;
}
