using Identity.Api.Models.Base;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class VerificationToken : BaseModel
{
    [Required]
    [PersonalData]
    public Guid UserId { get; set; }

    [Required]
    [ProtectedPersonalData]
    public string Token { get; set; }

    [Required]
    [PersonalData]
    public string TypeOfToken { get; set; }

    [Required]
    [PersonalData]
    public bool IsConfirmed { get; set; } = false;

    [Required]
    [PersonalData]
    public DateTimeOffset ExpiresAt { get; set; }

    [PersonalData]
    public DateTimeOffset? ConfirmedDate { get; set; } = null;
}
