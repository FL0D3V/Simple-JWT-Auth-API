using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Identity.Api.Dtos.Base;

namespace Identity.Api.Dtos;


public class ChangePasswordDto : ChangePasswordDtoBase
{
    [Required(ErrorMessage = "Old password is required")]
    [DataType(DataType.Password)]
    [NotMapped]
    public string OldPassword { get; set; } = string.Empty;
}