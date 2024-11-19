using Identity.Api.Models.Base;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class RefreshToken : BaseModel
{
    [Required]
    public Guid UserId { get; set; }

    [Required]
    public string Token { get; set; }

    [Required]
    public string LoginClientToken { get; set; }

    [Required]
    public bool Revoked { get; set; } = false;

    public DateTimeOffset? RevokedAt { get; set; } = null;

    [Required]
    public DateTimeOffset ExpiresAt { get; set; }
}
