using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Zoreal.OAuth2;

/// <summary>
/// The relying-party client. One instance per registered ZOREAL client;
/// thread-safe, so build it once at boot and share it (register it as a
/// singleton).
///
/// <code>
/// var zoreal = new ZorealOAuth2Client(new ZorealOAuth2ClientOptions
/// {
///     ClientId = configuration["Zoreal:ClientId"]!,
///     Auth = new ClientAuth.ClientSecretBasic(configuration["Zoreal:ClientSecret"]!),
/// });
///
/// var login = await zoreal.AuthenticateAsync(code, codeVerifier, nonce);
/// login.Sub;                        // the pairwise subject: your stable user key
/// await login.UserinfoAsync();      // Tier B claims (email, name, ...), fetched once
/// </code>
/// </summary>
public sealed class ZorealOAuth2Client : IDisposable
{
    public const string DefaultIssuer = "https://id.zoreal.com";

    /// <summary>
    /// The provider serves its JWKS with a 10-minute public cache; mirroring
    /// it here keeps a busy relying party off the endpoint without holding a
    /// rotated-out key longer than the provider itself would.
    /// </summary>
    public static readonly TimeSpan JwksTtl = TimeSpan.FromSeconds(600);

    public const string JwksCacheKey = "zoreal_oauth2_jwks";

    /// <summary>
    /// The assurance vocabulary, weakest to strongest. Verification accepts
    /// equal or stronger: an RP requiring zoreal.device is satisfied by a
    /// zoreal.live token, never the reverse.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, int> AcrOrder = new Dictionary<string, int>
    {
        ["zoreal.session"] = 0,
        ["zoreal.device"] = 1,
        ["zoreal.live"] = 2,
    };

    private const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public string ClientId { get; }
    public string Issuer { get; }

    private readonly ClientAuth _auth;
    private readonly IJwksCache _cache;
    private readonly HttpClient _http;

    public ZorealOAuth2Client(ZorealOAuth2ClientOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId))
            throw new ConfigurationException("client_id is required");
        if (string.IsNullOrWhiteSpace(options.Issuer))
            throw new ConfigurationException("issuer is required");

        ClientId = options.ClientId;
        Issuer = options.Issuer.TrimEnd('/');
        _auth = options.Auth;
        _cache = options.Cache ?? new InMemoryJwksCache();
        _http = new HttpClient(options.HttpMessageHandler ?? CreateHandler(options.Auth), disposeHandler: true)
        {
            Timeout = options.Timeout,
        };
    }

    /// <summary>
    /// The whole login, in order: exchange the code (with the PKCE verifier
    /// the browser SDK handed over), verify the ID token against the JWKS,
    /// check the nonce when the caller has it, and — when the caller passes
    /// <paramref name="acr"/> — refuse a token whose assurance is below it.
    /// Returns a <see cref="Login"/>; personal data is NOT fetched here,
    /// because the ID token never carries it and not every caller wants it —
    /// <see cref="Login.UserinfoAsync"/> fetches on first use.
    ///
    /// REQUESTING an assurance on the wire (the SDK's acr_values) is
    /// advisory; the signed acr claim is the proof, and this parameter is
    /// where a relying party that asked for a liveness check verifies it
    /// actually happened. An RP that requires zoreal.live and never passes
    /// <paramref name="acr"/> here has checked nothing.
    /// </summary>
    public async Task<Login> AuthenticateAsync(
        string code, string codeVerifier, string? nonce = null, string? acr = null,
        CancellationToken cancellationToken = default)
    {
        var tokens = await ExchangeAsync(code, codeVerifier, cancellationToken).ConfigureAwait(false);
        var claims = await VerifyIdTokenAsync(tokens.IdToken, nonce, acr, cancellationToken).ConfigureAwait(false);
        return new Login(this, claims, tokens.IdToken, tokens.AccessToken, tokens.Scope);
    }

    /// <summary>
    /// POST /token. The verifier is mandatory: PKCE is required for every
    /// ZOREAL client, and the browser SDK that generated it hands it to your
    /// frontend precisely so your backend can present it here. Client
    /// authentication travels per the configured <see cref="ClientAuth"/>.
    /// </summary>
    public async Task<TokenResponse> ExchangeAsync(
        string code, string codeVerifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(code))
            throw new ArgumentException("code is required", nameof(code));
        if (string.IsNullOrWhiteSpace(codeVerifier))
            throw new ArgumentException("code_verifier is required", nameof(codeVerifier));

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", codeVerifier),
            // Always present, whatever the auth method: the provider matches
            // the code against it.
            new("client_id", ClientId),
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{Issuer}/token");
        switch (_auth)
        {
            case ClientAuth.ClientSecretBasic basic:
                // The secret travels as the Basic password, never as a form field.
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ClientId}:{basic.ClientSecret}")));
                break;
            case ClientAuth.PrivateKeyJwt:
                form.Add(new("client_assertion_type", ClientAssertionType));
                form.Add(new("client_assertion", BuildClientAssertion()));
                break;
            case ClientAuth.None:
            case ClientAuth.TlsClientAuth:
                // Nothing on the form. A public client is held by PKCE alone;
                // an mTLS client's certificate travels on the connection, and
                // the provider's 501 for it comes back as an ExchangeException.
                break;
        }
        request.Content = new FormUrlEncodedContent(form);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var json = ParseJson(body);

        if (!response.IsSuccessStatusCode)
        {
            throw new ExchangeException(
                StringField(json, "error") ?? "server_error",
                StringField(json, "error_description") ?? $"the provider answered {(int)response.StatusCode}",
                (int)response.StatusCode);
        }

        var idToken = StringField(json, "id_token");
        if (string.IsNullOrEmpty(idToken))
            throw new ExchangeException("server_error", "no id_token in the token response");

        return new TokenResponse(
            idToken,
            StringField(json, "access_token"),
            StringField(json, "token_type"),
            NumberField(json, "expires_in"),
            StringField(json, "scope"));
    }

    /// <summary>
    /// ES256 against the provider's JWKS, plus iss, aud, exp, the nonce
    /// binding when the caller passes the nonce the SDK generated, and the
    /// assurance floor when the caller passes <paramref name="acr"/>. Returns
    /// the verified claims. There is no RS256 fallback on purpose: ZOREAL
    /// signs nothing else, and accepting a second algorithm is how algorithm
    /// confusion starts. An unknown kid drops the cached JWKS and refetches
    /// once, which is how a key rotation is absorbed.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, JsonElement>> VerifyIdTokenAsync(
        string idToken, string? nonce = null, string? acr = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(idToken))
            throw new VerificationException("no ID token to verify");

        var keys = await SigningKeysAsync(forceRefresh: false, cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateToken(idToken, keys);
        }
        catch (SecurityTokenSignatureKeyNotFoundException)
        {
            keys = await SigningKeysAsync(forceRefresh: true, cancellationToken).ConfigureAwait(false);
            try
            {
                ValidateToken(idToken, keys);
            }
            catch (Exception e) when (IsTokenRefusal(e))
            {
                throw new VerificationException(e.Message, e);
            }
        }
        catch (Exception e) when (IsTokenRefusal(e))
        {
            throw new VerificationException(e.Message, e);
        }

        var claims = DecodeClaims(idToken);
        if (!string.IsNullOrEmpty(nonce))
        {
            var tokenNonce = StringField(claims, "nonce");
            if (tokenNonce != nonce)
                throw new VerificationException("the ID token nonce is not the one this login started with");
        }
        if (!string.IsNullOrEmpty(acr))
            VerifyAcr(claims, acr);
        return claims;
    }

    /// <summary>
    /// Equal or stronger satisfies; anything else — weaker, missing, or a
    /// value outside the vocabulary — is refused. An unknown REQUIREMENT is a
    /// caller bug and says so plainly rather than failing every login.
    /// </summary>
    private static void VerifyAcr(IReadOnlyDictionary<string, JsonElement> claims, string required)
    {
        if (!AcrOrder.TryGetValue(required, out var requiredRank))
            throw new ConfigurationException(
                $"unknown required acr {required}; supported: {string.Join(", ", AcrOrder.Keys)}");

        var actual = StringField(claims, "acr");
        if (actual is not null && AcrOrder.TryGetValue(actual, out var actualRank) && actualRank >= requiredRank)
            return;

        throw new VerificationException(
            $"the ID token says acr {(actual is null ? "(none)" : $"\"{actual}\"")}, below the required {required}");
    }

    /// <summary>
    /// GET /userinfo with the Bearer access token from the exchange. This is
    /// the only place personal claims (email, profile.*) are served, and the
    /// access token lives ten minutes, so call it as part of handling the
    /// login rather than storing the token for later.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, JsonElement>> UserinfoAsync(
        string accessToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
            throw new ArgumentException("access_token is required", nameof(accessToken));

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{Issuer}/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var json = ParseJson(body);
            throw new UserinfoException(
                StringField(json, "error_description") ?? $"userinfo answered {(int)response.StatusCode}");
        }
        return ParseJson(body);
    }

    /// <summary>
    /// The RFC 7523 client assertion for one token request: iss and sub are
    /// the client_id, aud is the token endpoint, and the lifetime stays a few
    /// seconds inside the provider's 60-second maximum so ordinary clock skew
    /// does not push exp over it. The jti is fresh random bytes because the
    /// provider enforces single use.
    /// </summary>
    internal string BuildClientAssertion()
    {
        if (_auth is not ClientAuth.PrivateKeyJwt auth)
            throw new ConfigurationException("this client is not configured for private_key_jwt");

        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = ClientId,
            Audience = $"{Issuer}/token",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddSeconds(55),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = ClientId,
                ["jti"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)),
            },
            SigningCredentials = auth.SigningCredentials,
        };
        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }

    public void Dispose() => _http.Dispose();

    private static HttpMessageHandler CreateHandler(ClientAuth auth)
    {
        var handler = new HttpClientHandler();
        if (auth is ClientAuth.TlsClientAuth tls)
        {
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(tls.ClientCertificate);
        }
        return handler;
    }

    private void ValidateToken(string idToken, ICollection<SecurityKey> keys)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidateIssuer = true,
            ValidAudience = ClientId,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.EcdsaSha256 },
            IssuerSigningKeys = keys,
            ClockSkew = TimeSpan.Zero,
        };
        new JwtSecurityTokenHandler().ValidateToken(idToken, parameters, out _);
    }

    // The library's own message never carries the token; the IdentityModel
    // messages name the check that failed and hide claim values by default.
    private static bool IsTokenRefusal(Exception e) => e is SecurityTokenException or ArgumentException;

    private async Task<ICollection<SecurityKey>> SigningKeysAsync(bool forceRefresh, CancellationToken cancellationToken)
    {
        var json = forceRefresh ? null : _cache.Get(JwksCacheKey);
        if (json is null)
        {
            if (forceRefresh) _cache.Remove(JwksCacheKey);
            json = await FetchJwksAsync(cancellationToken).ConfigureAwait(false);
            _cache.Set(JwksCacheKey, json, JwksTtl);
        }

        try
        {
            return new JsonWebKeySet(json).GetSigningKeys();
        }
        catch (ArgumentException e)
        {
            throw new VerificationException("the provider JWKS could not be parsed", e);
        }
    }

    private async Task<string> FetchJwksAsync(CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try
        {
            response = await _http.GetAsync($"{Issuer}/jwks", cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new VerificationException($"could not fetch the provider JWKS: {e.Message}", e);
        }
        catch (TaskCanceledException e) when (!cancellationToken.IsCancellationRequested)
        {
            throw new VerificationException("could not fetch the provider JWKS: the request timed out", e);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                throw new VerificationException($"could not fetch the provider JWKS ({(int)response.StatusCode})");
            return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    // Only called on a token whose signature already verified.
    private static IReadOnlyDictionary<string, JsonElement> DecodeClaims(string jwt)
    {
        var payload = jwt.Split('.')[1];
        return ParseJson(Base64UrlEncoder.Decode(payload));
    }

    private static IReadOnlyDictionary<string, JsonElement> ParseJson(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body)
                ?? new Dictionary<string, JsonElement>();
        }
        catch (JsonException)
        {
            return new Dictionary<string, JsonElement>();
        }
    }

    private static string? StringField(IReadOnlyDictionary<string, JsonElement> json, string name) =>
        json.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static long? NumberField(IReadOnlyDictionary<string, JsonElement> json, string name) =>
        json.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt64()
            : null;
}
