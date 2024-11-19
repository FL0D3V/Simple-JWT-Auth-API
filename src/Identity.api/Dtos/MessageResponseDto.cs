namespace Identity.Api.Dtos;

public record MessageResponseDto
{
    public string Message { get; set; } = string.Empty;
    public int Code { get; set; }
}
