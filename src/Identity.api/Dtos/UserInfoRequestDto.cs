using Identity.Api.Enums;

namespace Identity.Api.Dtos;


public class UserInfoRequestDto
{
    public string UserName { get; set; }
    public string DisplayName { get; set; }
    public string Email { get; set; }
    public string LanguageCode { get; set; }
    public GenderCodes Gender { get; set; }
    public string? PhoneNumber { get; set; }
    public List<string> Roles { get; set; } = new();
    public DateTimeOffset CreatedDate { get; set; }
    public DateTimeOffset LastModifiedDate { get; set; }
}
