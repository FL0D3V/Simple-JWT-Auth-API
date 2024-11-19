using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Identity.Api.CustomAttributes;


/// <summary>
///     Validation attribute to indicate that a property field or parameter is a language code
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter, 
    AllowMultiple = false)]
public class LanguageCodeAttribute : ValidationAttribute
{
    private const string _pattern = @"^([a-zA-Z]+)(-{1}[a-zA-Z0-9]+){0,2}$";


    public LanguageCodeAttribute()
        : base()
    {
        Pattern = _pattern;
        MatchTimeoutInMilliseconds = 2000;
    }


    /// <summary>
    ///     Gets or sets the timeout to use when matching the regular expression pattern (in milliseconds)
    ///     (-1 means never timeout).
    /// </summary>
    public int MatchTimeoutInMilliseconds { get; set; }

    /// <summary>
    ///     Gets the regular expression pattern to use
    /// </summary>
    public string Pattern { get; }

    private Regex? Regex { get; set; }


    /// <summary>
    ///     Override of <see cref="ValidationAttribute.IsValid(object)" />
    /// </summary>
    /// <remarks>
    ///     This override performs the specific regular expression matching for a valid language code and checks also if the given code is found in the culture info list.
    /// </remarks>
    /// <param name="value">The value to test for validity.</param>
    /// <returns><c>true</c> if the given value matches the current regular expression pattern</returns>
    /// <exception cref="InvalidOperationException"> is thrown if the current attribute is ill-formed.</exception>
    /// <exception cref="ArgumentException"> is thrown if the <see cref="Pattern" /> is not a valid regular expression.</exception>
    public override bool IsValid(object? value)
    {
        SetupRegex();

        // Convert the value to a string
        string? langCode = Convert.ToString(value, CultureInfo.CurrentCulture);

        // Automatically pass if value is null or empty. RequiredAttribute should be used to assert a value is not empty.
        if (string.IsNullOrEmpty(langCode))
        {
            return true;
        }

        var m = Regex!.Match(langCode);

        // We are looking for an exact match, not just a search hit. This matches what
        // the RegularExpressionValidator control does
        var regexCheck = (m.Success && m.Index == 0 && m.Length == langCode.Length);

        // The given string is not valid!
        if (!regexCheck)
        {
            return false;
        }

        // Check if the checked language code is in the cultures list.
        var culture = CultureInfo.GetCultures(CultureTypes.AllCultures).FirstOrDefault(l => l.Name == langCode);

        // Culture not found!
        if (culture == null)
        {
            return false;
        }

        // Culture was found!
        return true;
    }


    private void SetupRegex()
    {
        if (Regex == null)
        {
            if (string.IsNullOrEmpty(Pattern))
            {
                throw new InvalidOperationException("Empty regex-pattern!");
            }

            Regex = MatchTimeoutInMilliseconds == -1
                ? new Regex(Pattern)
                : new Regex(Pattern, default(RegexOptions), TimeSpan.FromMilliseconds(MatchTimeoutInMilliseconds));
        }
    }
}