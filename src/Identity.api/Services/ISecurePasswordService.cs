namespace Identity.Api.Services
{
    public interface ISecurePasswordService
    {
        byte[] GenerateSalt();
        byte[] GetNewSalt(out byte[] salt);
        byte[] HashPassword(string password, byte[]? salt = null);
    }
}