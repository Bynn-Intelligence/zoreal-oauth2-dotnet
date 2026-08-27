using System.Text.Json;

namespace Zoreal.OAuth2;

/// <summary>
/// One verified login. The ID token claims are already checked when this
/// exists; userinfo is fetched on first use, because the ID token never
/// carries personal data and not every login needs any.
/// </summary>
public sealed class Login
{
    private readonly ZorealOAuth2Client _client;
    private Userinfo? _userinfo;

    /// <summary>The verified ID token claims.</summary>
    public IReadOnlyDictionary<string, JsonElement> Claims { get; }

    /// <summary>The raw compact JWT the claims came from.</summary>
    public string IdToken { get; }

    /// <summary>From the token response. The access token lives ten minutes.</summary>
    public string? AccessToken { get; }

    /// <summary>The granted scope, space-separated, as the provider issued it.</summary>
    public string? Scope { get; }

    internal Login(
        ZorealOAuth2Client client,
        IReadOnlyDictionary<string, JsonElement> claims,
        string idToken,
        string? accessToken,
        string? scope)
    {
        _client = client;
        Claims = claims;
        IdToken = idToken;
        AccessToken = accessToken;
        Scope = scope;
    }

    /// <summary>
    /// The pairwise subject: stable for your verified domain, meaningless to
    /// anyone else. This is the value to key accounts on — and it is derived
    /// from YOUR registered sector, so changing your asset's domain rotates
    /// every sub you have stored.
    /// </summary>
    public string? Sub => StringClaim("sub");

    /// <summary>
    /// How the login was authenticated: zoreal.live, zoreal.device or
    /// zoreal.session. Describes what happened, never what was requested.
    /// </summary>
    public string? Acr => StringClaim("acr");

    /// <summary>The authentication methods, e.g. hwk, face, user. Empty when absent.</summary>
    public IReadOnlyList<string> Amr =>
        Claims.TryGetValue("amr", out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .ToArray()
            : Array.Empty<string>();

    /// <summary>
    /// The assurance block ("zoreal" claim): uniqueness basis, verification
    /// month, chip liveness, trust tier, key protection. Null when absent.
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement>? Assurance =>
        Claims.TryGetValue("zoreal", out var value) && value.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(value.GetRawText())
            : null;

    /// <summary>
    /// zoreal.age scope: the registered thresholds arrive as booleans
    /// (age_over_18 and so on), never an age. Null when the threshold is not
    /// registered for your client, which is different from false.
    /// </summary>
    public bool? AgeOver(int threshold) =>
        Claims.TryGetValue($"age_over_{threshold}", out var value)
        && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : null;

    /// <summary>zoreal.nationality scope: ISO 3166-1 alpha-3, read from the chip.</summary>
    public string? Nationality => StringClaim("nationality");

    /// <summary>
    /// The Tier B claims, from /userinfo, fetched once and memoized. Throws
    /// <see cref="UserinfoException"/> when the endpoint refuses — catch it if
    /// your flow can continue without personal data, as a returning user
    /// matched on <see cref="Sub"/> can; a failed fetch is retried on the
    /// next call. Returns <see cref="Userinfo.Empty"/> without a fetch when
    /// the exchange carried no access token.
    /// </summary>
    public async Task<Userinfo> UserinfoAsync(CancellationToken cancellationToken = default)
    {
        var cached = Volatile.Read(ref _userinfo);
        if (cached is not null) return cached;

        var fetched = AccessToken is null
            ? Userinfo.Empty
            : new Userinfo(await _client.UserinfoAsync(AccessToken, cancellationToken).ConfigureAwait(false));

        // The first successful fetch wins; a concurrent second fetch of the
        // same ten-minute token returns the same claims anyway.
        Interlocked.CompareExchange(ref _userinfo, fetched, null);
        return _userinfo!;
    }

    private string? StringClaim(string name) =>
        Claims.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
