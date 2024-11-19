namespace Identity.Api.Helper;


public static class StringHelper
{
    public static string ToNormalized(this string text)
    {
        return text.ToUpper().Normalize();
    }
}
