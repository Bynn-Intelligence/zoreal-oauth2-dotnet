using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Zoreal.OAuth2.Tests;

/// <summary>
/// Offline plumbing: a P-256 keypair generated per test class, a JWKS built
/// from it, hand-rolled JWT signing (so any header and any claims can be
/// produced, including invalid ones), and an HttpMessageHandler stub so
/// nothing here touches the network.
/// </summary>
internal static class TestSupport
{
    public const string Issuer = "https://id.zoreal.example";
    public const string ClientId = "ast_test_client";

    public static ECDsa NewP256Key() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static string JwksJson(ECDsa key, string kid)
    {
        var p = key.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new
                {
                    kty = "EC",
                    crv = "P-256",
                    x = Base64UrlEncoder.Encode(p.Q.X!),
                    y = Base64UrlEncoder.Encode(p.Q.Y!),
                    kid,
                    use = "sig",
                    alg = "ES256",
                },
            },
        });
    }

    /// <summary>ES256-signs claims into a compact JWT, IEEE P1363 signature as JWS wants.</summary>
    public static string Sign(ECDsa key, string kid, Dictionary<string, object?> claims)
    {
        var header = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["alg"] = "ES256",
            ["typ"] = "JWT",
            ["kid"] = kid,
        });
        var signingInput =
            $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}." +
            $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(claims)))}";
        var signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";
    }

    /// <summary>An unsigned token with alg none, for the refusal test.</summary>
    public static string UnsignedToken(Dictionary<string, object?> claims)
    {
        var header = JsonSerializer.Serialize(new Dictionary<string, object?> { ["alg"] = "none", ["typ"] = "JWT" });
        return $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}." +
               $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(claims)))}.";
    }

    public static Dictionary<string, object?> BaseClaims(params (string Name, object? Value)[] overrides)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "7QK3-9F2M-XR84-B5NP",
            ["aud"] = ClientId,
            ["exp"] = now + 120,
            ["iat"] = now,
            ["nonce"] = "n-1",
            ["acr"] = "zoreal.device",
        };
        foreach (var (name, value) in overrides) claims[name] = value;
        return claims;
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(
                kv => Uri.UnescapeDataString(kv[0]),
                kv => kv.Length > 1 ? Uri.UnescapeDataString(kv[1].Replace('+', ' ')) : "");

    public static ZorealOAuth2Client BuildClient(
        StubHandler handler, ClientAuth? auth = null, IJwksCache? cache = null) =>
        new(new ZorealOAuth2ClientOptions
        {
            ClientId = ClientId,
            Issuer = Issuer,
            Auth = auth ?? ClientAuth.None.Instance,
            Cache = cache,
            HttpMessageHandler = handler,
        });
}

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, string, HttpResponseMessage> _respond;

    public List<(HttpRequestMessage Request, string Body)> Calls { get; } = new();

    public StubHandler(Func<HttpRequestMessage, string, HttpResponseMessage> respond) => _respond = respond;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? ""
            : await request.Content.ReadAsStringAsync(cancellationToken);
        Calls.Add((request, body));
        return _respond(request, body);
    }

    public int CountFor(string pathSuffix) =>
        Calls.Count(c => c.Request.RequestUri!.AbsolutePath.EndsWith(pathSuffix, StringComparison.Ordinal));
}
