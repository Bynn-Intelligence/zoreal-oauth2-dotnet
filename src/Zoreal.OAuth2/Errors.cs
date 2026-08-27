namespace Zoreal.OAuth2;

/// <summary>The base type every error this library raises derives from.</summary>
public class ZorealOAuth2Exception : Exception
{
    public ZorealOAuth2Exception(string message) : base(message) { }
    public ZorealOAuth2Exception(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>The client was built without something it cannot work without.</summary>
public sealed class ConfigurationException : ZorealOAuth2Exception
{
    public ConfigurationException(string message) : base(message) { }
    public ConfigurationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// The provider refused the code exchange. <see cref="OAuthError"/> is the
/// RFC 6749 error code and <see cref="Description"/> the provider's own
/// reason, verbatim: the provider's words are the only signal that says WHY
/// (a consumed code, a PKCE mismatch, a lapsed sector), and rewriting them
/// hides it.
/// </summary>
public sealed class ExchangeException : ZorealOAuth2Exception
{
    /// <summary>The RFC 6749 error code, e.g. "invalid_grant".</summary>
    public string OAuthError { get; }

    /// <summary>The provider's error_description, verbatim.</summary>
    public string Description { get; }

    /// <summary>The HTTP status of the refusal, when there was a response at all.</summary>
    public int? Status { get; }

    public ExchangeException(string oauthError, string description, int? status = null)
        : base($"{oauthError}: {description}")
    {
        OAuthError = oauthError;
        Description = description;
        Status = status;
    }
}

/// <summary>
/// The ID token did not verify: bad signature, wrong issuer or audience,
/// expired, or a nonce that was not the one this login started with.
/// </summary>
public sealed class VerificationException : ZorealOAuth2Exception
{
    public VerificationException(string message) : base(message) { }
    public VerificationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// /userinfo answered with anything but the claims. Callers that can live
/// without personal data (a returning user matched by sub) may catch this
/// and continue; callers that need the email should not.
/// </summary>
public sealed class UserinfoException : ZorealOAuth2Exception
{
    public UserinfoException(string message) : base(message) { }
}
