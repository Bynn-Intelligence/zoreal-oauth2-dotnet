using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static Zoreal.OAuth2.Tests.TestSupport;

namespace Zoreal.OAuth2.Tests;

/// <summary>
/// The private_key_jwt assertion the library builds: decoded and checked
/// claim by claim, and validated against the public half of the key, exactly
/// as the provider will.
/// </summary>
public sealed class ClientAssertionTests
{
    private static string EcPem(ECDsa key) => key.ExportPkcs8PrivateKeyPem();

    private static JwtSecurityToken Decode(string assertion) =>
        new JwtSecurityTokenHandler().ReadJwtToken(assertion);

    private static void AssertSignatureValid(string assertion, SecurityKey publicKey)
    {
        new JwtSecurityTokenHandler().ValidateToken(assertion, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKey = publicKey,
        }, out _);
    }

    [Fact]
    public async Task The_exchange_form_carries_the_assertion_and_its_type()
    {
        using var key = NewP256Key();
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, """{"id_token":"jwt-here"}"""));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromPem(EcPem(key)));

        await client.ExchangeAsync("code-1", "verifier-1");

        var form = ParseForm(handler.Calls.Single().Body);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        Assert.False(string.IsNullOrEmpty(form["client_assertion"]));
        // client_id still travels; the provider matches the code against it.
        Assert.Equal(ClientId, form["client_id"]);
    }

    [Fact]
    public void Iss_sub_aud_exp_iat_and_jti_are_what_the_provider_requires()
    {
        using var key = NewP256Key();
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromPem(EcPem(key)));

        var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jwt = Decode(client.BuildClientAssertion());
        var after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Assert.Equal(ClientId, jwt.Issuer);
        Assert.Equal(ClientId, jwt.Subject);
        Assert.Equal($"{Issuer}/token", Assert.Single(jwt.Audiences));

        var exp = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds();
        var iat = new DateTimeOffset(jwt.IssuedAt).ToUnixTimeSeconds();
        // Inside the provider's hard 60-second window, on both edges.
        Assert.InRange(iat, before - 1, after + 1);
        Assert.InRange(exp, before + 1, after + 60);
        Assert.True(exp - iat <= 60);

        Assert.False(string.IsNullOrEmpty(jwt.Payload.Jti));
        Assert.Equal("ES256", jwt.Header.Alg);
    }

    [Fact]
    public void Every_assertion_gets_a_fresh_jti()
    {
        using var key = NewP256Key();
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromPem(EcPem(key)));

        var first = Decode(client.BuildClientAssertion()).Payload.Jti;
        var second = Decode(client.BuildClientAssertion()).Payload.Jti;

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void The_assertion_verifies_against_the_public_key_and_carries_the_kid()
    {
        using var key = NewP256Key();
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromPem(EcPem(key), "kid-42"));

        var assertion = client.BuildClientAssertion();

        Assert.Equal("kid-42", Decode(assertion).Header.Kid);
        using var publicKey = ECDsa.Create(key.ExportParameters(false));
        AssertSignatureValid(assertion, new ECDsaSecurityKey(publicKey));
    }

    [Fact]
    public void A_sec1_ec_pem_works_too()
    {
        using var key = NewP256Key();
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromPem(key.ExportECPrivateKeyPem()));

        Assert.Equal("ES256", Decode(client.BuildClientAssertion()).Header.Alg);
    }

    [Fact]
    public void An_rsa_key_signs_rs256()
    {
        using var key = RSA.Create(2048);
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromPem(key.ExportPkcs8PrivateKeyPem()));

        var assertion = client.BuildClientAssertion();

        Assert.Equal("RS256", Decode(assertion).Header.Alg);
        using var publicKey = RSA.Create(key.ExportParameters(false));
        AssertSignatureValid(assertion, new RsaSecurityKey(publicKey));
    }

    [Fact]
    public void A_private_jwk_works_and_keeps_its_kid()
    {
        using var key = NewP256Key();
        var p = key.ExportParameters(true);
        var jwk = System.Text.Json.JsonSerializer.Serialize(new
        {
            kty = "EC",
            crv = "P-256",
            x = Base64UrlEncoder.Encode(p.Q.X!),
            y = Base64UrlEncoder.Encode(p.Q.Y!),
            d = Base64UrlEncoder.Encode(p.D!),
            kid = "jwk-kid",
        });
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler, ClientAuth.PrivateKeyJwt.FromJwk(jwk));

        var assertion = client.BuildClientAssertion();

        var decoded = Decode(assertion);
        Assert.Equal("ES256", decoded.Header.Alg);
        Assert.Equal("jwk-kid", decoded.Header.Kid);
        using var publicKey = ECDsa.Create(key.ExportParameters(false));
        AssertSignatureValid(assertion, new ECDsaSecurityKey(publicKey));
    }

    [Fact]
    public void A_curve_other_than_p256_is_refused_at_configuration()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<ConfigurationException>(
            () => ClientAuth.PrivateKeyJwt.FromPem(key.ExportPkcs8PrivateKeyPem()));
    }

    [Fact]
    public void A_jwk_without_the_private_part_is_refused()
    {
        using var key = NewP256Key();
        var p = key.ExportParameters(false);
        var publicJwk = System.Text.Json.JsonSerializer.Serialize(new
        {
            kty = "EC",
            crv = "P-256",
            x = Base64UrlEncoder.Encode(p.Q.X!),
            y = Base64UrlEncoder.Encode(p.Q.Y!),
        });
        Assert.Throws<ConfigurationException>(() => ClientAuth.PrivateKeyJwt.FromJwk(publicJwk));
    }
}
