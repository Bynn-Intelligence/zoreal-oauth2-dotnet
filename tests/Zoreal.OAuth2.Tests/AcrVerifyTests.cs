using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using static Zoreal.OAuth2.Tests.TestSupport;

namespace Zoreal.OAuth2.Tests;

/// <summary>
/// The assurance floor at verification: the acr_values the frontend SDK put
/// on the wire was advisory, the signed acr claim is the proof, and this is
/// the check.
/// </summary>
public sealed class AcrVerifyTests : IDisposable
{
    private const string Kid = "k1";

    private readonly ECDsa _key = NewP256Key();
    private readonly ZorealOAuth2Client _client;

    public AcrVerifyTests()
    {
        var jwks = JwksJson(_key, Kid);
        var handler = new StubHandler((request, _) =>
            request.RequestUri!.AbsolutePath.EndsWith("/jwks", StringComparison.Ordinal)
                ? Json(HttpStatusCode.OK, jwks)
                : Json(HttpStatusCode.NotFound, "{}"));
        _client = BuildClient(handler);
    }

    public void Dispose()
    {
        _client.Dispose();
        _key.Dispose();
    }

    private string Token(string? acr)
    {
        var claims = BaseClaims();
        if (acr is null) claims.Remove("acr");
        else claims["acr"] = acr;
        return Sign(_key, Kid, claims);
    }

    [Fact]
    public async Task Equal_acr_satisfies()
    {
        var claims = await _client.VerifyIdTokenAsync(Token("zoreal.live"), acr: "zoreal.live");
        Assert.Equal("zoreal.live", claims["acr"].GetString());
    }

    [Fact]
    public async Task Stronger_acr_satisfies()
    {
        var claims = await _client.VerifyIdTokenAsync(Token("zoreal.live"), acr: "zoreal.device");
        Assert.Equal("zoreal.live", claims["acr"].GetString());
    }

    [Fact]
    public async Task Weaker_acr_is_refused()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Token("zoreal.device"), acr: "zoreal.live"));
    }

    [Fact]
    public async Task Missing_acr_is_refused_when_required()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Token(null), acr: "zoreal.session"));
    }

    [Fact]
    public async Task Unknown_required_acr_is_a_caller_bug()
    {
        await Assert.ThrowsAsync<ConfigurationException>(
            () => _client.VerifyIdTokenAsync(Token("zoreal.live"), acr: "zoreal.liveness"));
    }

    [Fact]
    public async Task No_required_acr_checks_nothing()
    {
        var claims = await _client.VerifyIdTokenAsync(Token(null));
        Assert.False(claims.ContainsKey("acr"));
    }

    [Fact]
    public void Login_conveniences()
    {
        var live = LoginWithAcr("zoreal.live");
        Assert.True(live.IsLive);
        Assert.True(live.SatisfiesAcr("zoreal.device"));
        Assert.False(live.SatisfiesAcr("made.up"));

        var device = LoginWithAcr("zoreal.device");
        Assert.False(device.IsLive);
        Assert.False(device.SatisfiesAcr("zoreal.live"));
    }

    private Login LoginWithAcr(string acr)
    {
        var claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            $$"""{"acr":"{{acr}}"}""")!;
        return new Login(_client, claims, "x", accessToken: null, scope: null);
    }
}
