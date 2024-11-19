namespace Identity.Api.Extensions
{
    public static class DateTimeExtensions
    {
        // Convert datetime to UNIX time
        public static long ToUnixTime(this DateTime dateTime)
        {
            DateTimeOffset dto = new(dateTime.ToUniversalTime());
            return dto.ToUnixTimeSeconds();
        }

        // Convert datetime to UNIX time including miliseconds
        public static long ToUnixTimeMilliSeconds(this DateTime dateTime)
        {
            DateTimeOffset dto = new(dateTime.ToUniversalTime());
            return dto.ToUnixTimeMilliseconds();
        }
    }
}
