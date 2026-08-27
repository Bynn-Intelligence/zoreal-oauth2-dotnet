using System.Net;
using System.Security.Cryptography;
using Xunit;
using static Zoreal.OAuth2.Tests.TestSupport;

namespace Zoreal.OAuth2.Tests;

/// <summary>
/// Offline ID token verification: the JWKS is served by the stub transport,
/// signed with a P-256 key generated here. Nothing touches the network.
/// </summary>
public sealed class VerifyIdTokenTests : IDisposable
{
    private const string Kid = "k1";

    private readonly ECDsa _key = NewP256Key();
    private readonly StubHandler _handler;
    private readonly ZorealOAuth2Client _client;

    public VerifyIdTokenTests()
    {
        var jwks = JwksJson(_key, Kid);
        _handler = new StubHandler((request, _) =>
            request.RequestUri!.AbsolutePath.EndsWith("/jwks", StringComparison.Ordinal)
                ? Json(HttpStatusCode.OK, jwks)
                : Json(HttpStatusCode.NotFound, "{}"));
        _client = BuildClient(_handler);
    }

    public void Dispose()
    {
        _client.Dispose();
        _key.Dispose();
    }

    [Fact]
    public async Task Valid_token_verifies_and_returns_claims()
    {
        var claims = await _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims()), "n-1");
        Assert.Equal("7QK3-9F2M-XR84-B5NP", claims["sub"].GetString());
        Assert.Equal("zoreal.device", claims["acr"].GetString());
    }

    [Fact]
    public async Task Nonce_mismatch_is_refused()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims()), "other"));
    }

    [Fact]
    public async Task Nonce_is_not_checked_when_caller_has_none()
    {
        var claims = await _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims()));
        Assert.Equal("n-1", claims["nonce"].GetString());
    }

    [Fact]
    public async Task Wrong_audience_is_refused()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims(("aud", "ast_other")))));
    }

    [Fact]
    public async Task Wrong_issuer_is_refused()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims(("iss", "https://evil.example")))));
    }

    [Fact]
    public async Task Expired_token_is_refused()
    {
        var expired = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 120;
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims(("exp", expired)))));
    }

    [Fact]
    public async Task Token_without_exp_is_refused()
    {
        var claims = BaseClaims();
        claims.Remove("exp");
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(Sign(_key, Kid, claims)));
    }

    [Fact]
    public async Task Foreign_key_with_unknown_kid_is_refused_after_one_refetch()
    {
        using var foreign = NewP256Key();
        var token = Sign(foreign, "k-foreign", BaseClaims());

        await Assert.ThrowsAsync<VerificationException>(() => _client.VerifyIdTokenAsync(token));

        // The unknown kid invalidated the cache and refetched exactly once:
        // the initial fetch plus one refresh, never a loop.
        Assert.Equal(2, _handler.CountFor("/jwks"));
    }

    [Fact]
    public async Task Foreign_key_under_the_known_kid_is_refused_without_refetch()
    {
        using var foreign = NewP256Key();
        var token = Sign(foreign, Kid, BaseClaims());

        await Assert.ThrowsAsync<VerificationException>(() => _client.VerifyIdTokenAsync(token));

        // The kid matched, the signature failed: a bad signature is not a
        // rotation, so the cache stays.
        Assert.Equal(1, _handler.CountFor("/jwks"));
    }

    [Fact]
    public async Task Unsigned_token_is_refused()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync(UnsignedToken(BaseClaims())));
    }

    [Fact]
    public async Task Garbage_is_refused()
    {
        await Assert.ThrowsAsync<VerificationException>(
            () => _client.VerifyIdTokenAsync("not-a-jwt"));
    }

    [Fact]
    public async Task Jwks_is_cached_between_verifications()
    {
        await _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims()));
        await _client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims()));
        Assert.Equal(1, _handler.CountFor("/jwks"));
    }

    [Fact]
    public async Task An_injected_cache_is_used_instead_of_the_transport()
    {
        var cache = new InMemoryJwksCache();
        cache.Set(ZorealOAuth2Client.JwksCacheKey, JwksJson(_key, Kid), ZorealOAuth2Client.JwksTtl);
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.InternalServerError, "{}"));
        using var client = BuildClient(handler, cache: cache);

        var claims = await client.VerifyIdTokenAsync(Sign(_key, Kid, BaseClaims()), "n-1");

        Assert.Equal("7QK3-9F2M-XR84-B5NP", claims["sub"].GetString());
        Assert.Empty(handler.Calls);
    }
}
