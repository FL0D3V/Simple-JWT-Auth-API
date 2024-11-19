using System.ComponentModel.DataAnnotations;

namespace Identity.Api.Dtos
{
    public class RoleRequestDto
    {
        [Required]
        [RegularExpression(@"^[\w\--[\r\n\s_]]+$")]
        public string Name { get; set; }

        [Required]
        public string Description { get; set; }
    }
}
