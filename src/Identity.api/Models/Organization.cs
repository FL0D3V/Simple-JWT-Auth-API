using Identity.Api.Models.Base;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class Organization : ExtendedBaseModel
{
    [Required]
    public string Name { get; set; }                        // e.g. Example Company

    [Required]
    public string LegalForm { get; set; }                   // e.g. GmbH, Corp., etc.

    public string? Description { get; set; } = null;

    [Url]
    public string? WebsiteUrl { get; set; } = null;

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    public bool EmailConfirmed { get; set; } = false;

    [Required]
    public DateTimeOffset? EmailConfirmedDate { get; set; } = null;

    [Required]
    [EmailAddress]
    public string NormalizedEmail { get; set; }

    [Required]
    public Guid AddressId { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; } = null;

    [DataType(DataType.Upload)]
    public byte[]? Logo { get; set; } = null;
}