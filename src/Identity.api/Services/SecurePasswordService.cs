using System.Security.Cryptography;

namespace Identity.Api.Services;


public class SecurePasswordService : ISecurePasswordService
{
    private SecurePasswordOptions _options = null;
    private SecurePasswordValidation _validationOptions = null;


    public SecurePasswordService()
    {
        InitService();
    }

    public SecurePasswordService(SecurePasswordOptions? options = null)
    {
        InitService(options);
    }

    private void InitService(SecurePasswordOptions? options = null)
    {
        _options = options ?? new DefaultSecurePasswordOptions();
        _validationOptions = SecurePasswordValidation.DefaultValidationOptions;

        // Validates the password options
        _validationOptions.ValidatePasswordOptions(_options);
    }
    


    public byte[] GenerateSalt()
    {
        var bytes = new byte[_options.HashBytesCount];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
            return bytes;
        }
    }

    private string GetFinalPassword(string password)
    {
        return string.Concat(password, _options.Pepper);
    }

    public byte[] GetNewSalt(out byte[] salt)
    {
        var saltBytes = GenerateSalt();
        return salt = saltBytes;
    }

    public byte[] HashPassword(string password, byte[]? salt = null)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("The password must not be null or empty");
        }

        var saltBytes = salt ?? GenerateSalt();

        var hashed = Rfc2898DeriveBytes.Pbkdf2(GetFinalPassword(password),
                                               saltBytes,
                                               _options.PasswordHashingIterations,
                                               _options.HashingAlgorithm,
                                               _options.PasswordBytesLength);

        return hashed;
    }
}


public class SecurePasswordValidation
{
    private static SecurePasswordValidation _defaultValidationOptions = null;
    public static SecurePasswordValidation DefaultValidationOptions => _defaultValidationOptions ??= new SecurePasswordValidation(16, 10000, 32);



    public int MinHashBytesCount { get; }
    public int MinPasswordHashingIterations { get; }
    public int MinPasswordBytesLength { get; }
    public HashAlgorithmName HashingAlgorithmCheck { get; }



    public SecurePasswordValidation(int minHashBytesCount, int minPasswordHashingIter, int minPasswordBytesLen)
    {
        MinHashBytesCount = minHashBytesCount;
        MinPasswordHashingIterations = minPasswordHashingIter;
        MinPasswordBytesLength = minPasswordBytesLen;
        HashingAlgorithmCheck = default;
    }


    /// <summary>
    /// Validates the given password options with the given validation parameters.
    /// </summary>
    /// <param name="options">The passwords hashing options</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public void ValidatePasswordOptions(SecurePasswordOptions? options)
    {
        if (options == null)
        {
            throw new ArgumentNullException($"The {nameof(SecurePasswordOptions)} must not be null!");
        }

        if (options.HashBytesCount < MinHashBytesCount)
        {
            throw new ArgumentException($"The password option {nameof(SecurePasswordOptions.HashBytesCount)} is to low! Permitted is everithing >= {MinHashBytesCount}!");
        }

        if (options.PasswordHashingIterations < MinPasswordHashingIterations)
        {
            throw new ArgumentException($"The password option {nameof(SecurePasswordOptions.PasswordHashingIterations)} is to low! Permitted is everithing >= {MinPasswordHashingIterations}!");
        }

        if (options.PasswordBytesLength < MinPasswordBytesLength)
        {
            throw new ArgumentException($"The password option {nameof(SecurePasswordOptions.PasswordBytesLength)} is to low! Permitted is everithing >= {MinPasswordBytesLength}!");
        }

        if (options.HashingAlgorithm == HashingAlgorithmCheck)
        {
            throw new ArgumentException($"The password options {nameof(SecurePasswordOptions.HashingAlgorithm)} is not set!");
        }

        if (options.HashingAlgorithm == HashAlgorithmName.MD5 || options.HashingAlgorithm == HashAlgorithmName.SHA1)
        {
            throw new ArgumentException($"The given password options {nameof(SecurePasswordOptions.HashingAlgorithm)} is consided insecure!");
        }
    }
}



public class SecurePasswordOptions
{
    public SecurePasswordOptions()
    {
    }

    public SecurePasswordOptions(int hashBytesCount, int passwordHashingIterations, int passwordBytesLength, string? pepper = null)
    {
        HashBytesCount = hashBytesCount;
        PasswordHashingIterations = passwordHashingIterations;
        PasswordBytesLength = passwordBytesLength;
        Pepper = pepper;
    }


    /// <summary>
    /// 16 is minimum for security.
    /// </summary>
    public int HashBytesCount { get; set; }

    /// <summary>
    /// Higher is better but will slow down the algorithm. Must be above 10000
    /// </summary>
    public int PasswordHashingIterations { get; set; }

    /// <summary>
    /// The output password bytes array length. Must be above 32!
    /// </summary>
    public int PasswordBytesLength { get; set; }

    /// <summary>
    /// The password hashing algorithm to use!
    /// </summary>
    public HashAlgorithmName HashingAlgorithm { get; set; }

    /// <summary>
    /// The application specific extra password security key. This key is not stored in a database, only in the service itself!
    /// Like in the "appsettings.json" file.
    /// </summary>
    public string? Pepper { get; set; }
}



public class DefaultSecurePasswordOptions : SecurePasswordOptions
{
    public const SecurePasswordOptions DefaultOptions = null;

    public DefaultSecurePasswordOptions()
        : base()
    {
        Init();
    }

    public DefaultSecurePasswordOptions(string? pepper = null)
        : base()
    {
        Init(pepper);
    }

    private void Init(string? pepper = null)
    {
        HashBytesCount = 32;
        PasswordHashingIterations = 100000;
        PasswordBytesLength = 512;
        HashingAlgorithm = HashAlgorithmName.SHA512;
        Pepper = pepper;
    }
}

public static class PasswordServiceExtension
{
    public static IServiceCollection AddSecurePasswordService(this IServiceCollection services)
    {
        return services.AddSingleton<ISecurePasswordService, SecurePasswordService>();
    }

    public static IServiceCollection AddSecurePasswordService(this IServiceCollection services, Action<SecurePasswordOptions> configureOptions)
    {
        var options = new SecurePasswordOptions();

        configureOptions(options);

        return services.AddSingleton<ISecurePasswordService>(factory =>
        {
            return new SecurePasswordService(options);
        });
    }
}