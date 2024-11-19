using Identity.Api.Models;

namespace Identity.Api.Extensions
{
    public static class UserExtension
    {
        public static string DisplayName(this User user)
        {
            return string.IsNullOrEmpty(user.Title) ?
                string.Concat(user.FirstName, " ", user.LastName) : 
                string.Concat(user.Title, " ", user.FirstName, " ", user.LastName);
        }
    }
}
