using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using static Zoreal.OAuth2.Tests.TestSupport;

namespace Zoreal.OAuth2.Tests;

/// <summary>
/// The whole login offline: a stub provider serving /token, /jwks and
/// /userinfo, with a real ES256-signed ID token.
/// </summary>
public sealed class LoginTests : IDisposable
{
    private const string Kid = "k1";

    private readonly ECDsa _key = NewP256Key();

    public void Dispose() => _key.Dispose();

    private string SignedIdToken(params (string Name, object? Value)[] overrides) =>
        Sign(_key, Kid, BaseClaims(overrides));

    private StubHandler Provider(string idToken, bool withAccessToken = true)
    {
        var tokenBody = withAccessToken
            ? $$"""{"id_token":"{{idToken}}","access_token":"at-1","token_type":"Bearer","expires_in":600,"scope":"openid email"}"""
            : $$"""{"id_token":"{{idToken}}"}""";
        var jwks = JwksJson(_key, Kid);
        return new StubHandler((request, _) => request.RequestUri!.AbsolutePath switch
        {
            var p when p.EndsWith("/token", StringComparison.Ordinal) => Json(HttpStatusCode.OK, tokenBody),
            var p when p.EndsWith("/jwks", StringComparison.Ordinal) => Json(HttpStatusCode.OK, jwks),
            var p when p.EndsWith("/userinfo", StringComparison.Ordinal) => Json(
                HttpStatusCode.OK,
                """{"sub":"7QK3-9F2M-XR84-B5NP","email":"holder@example.com","email_verified":true,"name":"Maja Lindqvist","given_name":"Maja","family_name":"Lindqvist"}"""),
            _ => Json(HttpStatusCode.NotFound, "{}"),
        });
    }

    [Fact]
    public async Task Authenticate_exchanges_verifies_and_reads_the_claims()
    {
        var idToken = SignedIdToken(
            ("acr", "zoreal.live"),
            ("amr", new[] { "hwk", "face", "user" }),
            ("age_over_18", true),
            ("nationality", "SWE"),
            ("zoreal", new Dictionary<string, object?> { ["trust_tier"] = "high", ["chip_liveness_proven"] = true }));
        var handler = Provider(idToken);
        using var client = BuildClient(handler);

        var login = await client.AuthenticateAsync("code-1", "verifier-1", "n-1");

        Assert.Equal("7QK3-9F2M-XR84-B5NP", login.Sub);
        Assert.Equal("zoreal.live", login.Acr);
        Assert.Equal(new[] { "hwk", "face", "user" }, login.Amr);
        Assert.Equal(idToken, login.IdToken);
        Assert.Equal("at-1", login.AccessToken);
        Assert.Equal("openid email", login.Scope);
        Assert.True(login.AgeOver(18));
        Assert.Null(login.AgeOver(65));
        Assert.Equal("SWE", login.Nationality);
        Assert.Equal("high", login.Assurance!["trust_tier"].GetString());
        Assert.True(login.Assurance["chip_liveness_proven"].GetBoolean());
    }

    [Fact]
    public async Task Userinfo_is_fetched_lazily_once_and_memoized()
    {
        var handler = Provider(SignedIdToken());
        using var client = BuildClient(handler);

        var login = await client.AuthenticateAsync("code-1", "verifier-1", "n-1");
        Assert.Equal(0, handler.CountFor("/userinfo"));

        var first = await login.UserinfoAsync();
        var second = await login.UserinfoAsync();

        Assert.Equal(1, handler.CountFor("/userinfo"));
        Assert.Same(first, second);
        Assert.Equal("holder@example.com", first.Email);
        Assert.True(first.EmailVerified);
        Assert.Equal("Maja Lindqvist", first.Name);
        Assert.Equal("Maja", first.GivenName);
        Assert.Equal("Lindqvist", first.FamilyName);
        Assert.Null(first.Birthdate);
        Assert.Null(first.Portrait);
    }

    [Fact]
    public async Task Without_an_access_token_userinfo_is_empty_and_never_fetched()
    {
        var handler = Provider(SignedIdToken(), withAccessToken: false);
        using var client = BuildClient(handler);

        var login = await client.AuthenticateAsync("code-1", "verifier-1", "n-1");
        var userinfo = await login.UserinfoAsync();

        Assert.Same(Userinfo.Empty, userinfo);
        Assert.Empty(userinfo.Claims);
        Assert.Null(userinfo.Email);
        Assert.False(userinfo.EmailVerified);
        Assert.Equal(0, handler.CountFor("/userinfo"));
    }

    [Fact]
    public async Task A_substituted_nonce_fails_the_whole_authenticate()
    {
        var handler = Provider(SignedIdToken(("nonce", "n-substituted")));
        using var client = BuildClient(handler);

        await Assert.ThrowsAsync<VerificationException>(
            () => client.AuthenticateAsync("code-1", "verifier-1", "n-1"));
    }

    [Fact]
    public async Task Login_conveniences_are_null_not_throwing_when_claims_are_absent()
    {
        var handler = Provider(SignedIdToken());
        using var client = BuildClient(handler);

        var login = await client.AuthenticateAsync("code-1", "verifier-1", "n-1");

        Assert.Null(login.Nationality);
        Assert.Null(login.AgeOver(18));
        Assert.Null(login.Assurance);
        Assert.Empty(login.Amr);
    }

    [Fact]
    public void Client_configuration_is_checked_at_construction()
    {
        Assert.Throws<ConfigurationException>(() => new ZorealOAuth2Client(
            new ZorealOAuth2ClientOptions { ClientId = " " }));
        Assert.Throws<ConfigurationException>(() => new ZorealOAuth2Client(
            new ZorealOAuth2ClientOptions { ClientId = ClientId, Issuer = "" }));
        Assert.Throws<ConfigurationException>(() => new ClientAuth.ClientSecretBasic(""));
    }

    [Fact]
    public void Nothing_secret_leaks_through_ToString()
    {
        Assert.DoesNotContain("s3cret", new ClientAuth.ClientSecretBasic("s3cret").ToString());
        var tokens = new TokenResponse("id-jwt", "at-1", "Bearer", 600, "openid");
        Assert.DoesNotContain("id-jwt", tokens.ToString());
        Assert.DoesNotContain("at-1", tokens.ToString());
    }
}
