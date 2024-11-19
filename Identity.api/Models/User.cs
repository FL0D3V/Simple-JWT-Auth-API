using Identity.Api.Enums;
using Identity.Api.Models.Base;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class User : ExtendedBaseModel
{
    // Base user-informations:

    [Required]
    [ProtectedPersonalData]
    public string UserName { get; set; }

    [Required]
    [PersonalData]
    public DateTimeOffset LastChangedUserNameDate { get; set; } = DateTimeOffset.UtcNow;

    [Required]
    [EmailAddress]
    [ProtectedPersonalData]
    public string Email { get; set; }

    [Required]
    [EmailAddress]
    [ProtectedPersonalData]
    public string NormalizedEmail { get; set; }

    [PersonalData]
    [Required]
    public bool EmailConfirmed { get; set; } = false;

    [PersonalData]
    public DateTimeOffset? EmailConfirmedDate { get; set; } = null;

    [Required]
    [DataType(DataType.Password)]
    public byte[] Password { get; set; }

    [Required]
    public byte[] PasswordSalt { get; set; }

    [Required]
    public DateTimeOffset LastChangedPasswordDate { get; set; }

    [Required]
    public List<Role> Roles { get; set; } = new();                      // TODO: Redo in future

    //public int AccessFailedCount { get; set; } = 0;

    [PersonalData]
    [Required]
    public bool TwoFactorEnabled { get; set; } = false;

    [Required]
    public bool LockoutActive { get; set; } = false;

    public DateTimeOffset? LockoutEndDate { get; set; } = null;



    // Other user-informations:

    [PersonalData]
    public string? Title { get; set; } = null;

    [Required]
    [PersonalData]
    public string FirstName { get; set; }

    [Required]
    [PersonalData]
    public string LastName { get; set; }

    [Required]
    [PersonalData]
    public string LanguageCode { get; set; }

    [PersonalData]
    [DataType(DataType.Upload)]
    public byte[]? ProfilePicture { get; set; } = null;

    //[Required]
    [PersonalData]
    public byte[]? Signature { get; set; } = null;                          // TODO: Required in future!

    [Required]
    [PersonalData]
    [EnumDataType(typeof(GenderCodes))]                                    // TODO: Check if needed!
    public GenderCodes Gender { get; set; }

    [ProtectedPersonalData]
    [Phone]
    public string? PhoneNumber { get; set; } = null;

    [Required]
    [PersonalData]
    public bool PhoneNumberConfirmed { get; set; } = false;

    [PersonalData]
    public DateTimeOffset? PhoneNumberConfirmedDate { get; set; } = null;
}
