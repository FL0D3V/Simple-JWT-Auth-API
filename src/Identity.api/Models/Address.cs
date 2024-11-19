using Identity.Api.Models.Base;
using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Models;


public class Address : ExtendedBaseModel
{
    [Required]
    public string CountryCode { get; set; }             // AT -> ISO-Standard

    [Required]
    public string State { get; set; }                   // Carinthia

    [Required]
    public string Street { get; set; }                  // Musterstraße

    [Required]
    public string City { get; set; }                    // Musterstadt

    [Required]
    public string StreetNumber { get; set; }            // 10

    [Required]
    public string ZipCode { get; set; }                 // 2341

    public string? Floor { get; set; } = null;          // 5

    public string? Room { get; set; } = null;           // 20
}
