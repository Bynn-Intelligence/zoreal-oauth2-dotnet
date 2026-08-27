namespace Zoreal.OAuth2;

/// <summary>
/// Everything a <see cref="ZorealOAuth2Client"/> is built from. Build one
/// client at boot and share it; it is thread-safe.
/// </summary>
public sealed record ZorealOAuth2ClientOptions
{
    /// <summary>Your registered client_id (ast_...). It is also your asset token.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The provider. The value must match the iss inside the tokens exactly:
    /// it is compared, not normalized.
    /// </summary>
    public string Issuer { get; init; } = ZorealOAuth2Client.DefaultIssuer;

    /// <summary>
    /// How the client authenticates at the token endpoint. Defaults to
    /// <see cref="ClientAuth.None"/>, the public-client posture, where PKCE
    /// is the only proof.
    /// </summary>
    public ClientAuth Auth { get; init; } = ClientAuth.None.Instance;

    /// <summary>Optional shared store for the provider's JWKS.</summary>
    public IJwksCache? Cache { get; init; }

    /// <summary>Timeout for every provider call.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Overrides the HTTP transport, which is how the tests stay offline.
    /// When set together with <see cref="ClientAuth.TlsClientAuth"/>, the
    /// handler you pass wins and attaching the client certificate to it is
    /// your job.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }
}
