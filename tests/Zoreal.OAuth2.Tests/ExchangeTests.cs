using System.Net;
using Xunit;
using static Zoreal.OAuth2.Tests.TestSupport;

namespace Zoreal.OAuth2.Tests;

/// <summary>
/// The code exchange over a stub transport: what travels on the form and the
/// headers for each client authentication method, and how the provider's
/// refusals map to <see cref="ExchangeException"/>.
/// </summary>
public sealed class ExchangeTests
{
    private const string SuccessBody =
        """{"id_token":"jwt-here","access_token":"at-1","token_type":"Bearer","expires_in":600,"scope":"openid zoreal.age"}""";

    private static StubHandler TokenHandler(HttpStatusCode status = HttpStatusCode.OK, string body = SuccessBody) =>
        new((_, _) => Json(status, body));

    [Fact]
    public async Task Success_maps_the_token_response()
    {
        var handler = TokenHandler();
        using var client = BuildClient(handler);

        var tokens = await client.ExchangeAsync("code-1", "verifier-1");

        Assert.Equal("jwt-here", tokens.IdToken);
        Assert.Equal("at-1", tokens.AccessToken);
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.Equal(600, tokens.ExpiresIn);
        Assert.Equal("openid zoreal.age", tokens.Scope);
    }

    [Fact]
    public async Task The_form_carries_the_grant_and_the_pkce_verifier()
    {
        var handler = TokenHandler();
        using var client = BuildClient(handler);

        await client.ExchangeAsync("code-1", "verifier-1");

        var form = ParseForm(handler.Calls.Single().Body);
        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal("code-1", form["code"]);
        Assert.Equal("verifier-1", form["code_verifier"]);
        Assert.Equal(ClientId, form["client_id"]);
    }

    [Fact]
    public async Task A_public_client_sends_no_credentials()
    {
        var handler = TokenHandler();
        using var client = BuildClient(handler, ClientAuth.None.Instance);

        await client.ExchangeAsync("code-1", "verifier-1");

        var (request, body) = handler.Calls.Single();
        Assert.Null(request.Headers.Authorization);
        var form = ParseForm(body);
        Assert.False(form.ContainsKey("client_assertion"));
        Assert.False(form.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task Client_secret_basic_travels_as_the_basic_header_never_the_form()
    {
        var handler = TokenHandler();
        using var client = BuildClient(handler, new ClientAuth.ClientSecretBasic("s3cret"));

        await client.ExchangeAsync("code-1", "verifier-1");

        var (request, body) = handler.Calls.Single();
        Assert.Equal("Basic", request.Headers.Authorization!.Scheme);
        Assert.Equal(
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{ClientId}:s3cret")),
            request.Headers.Authorization.Parameter);
        var form = ParseForm(body);
        Assert.False(form.ContainsKey("client_secret"));
        // The form still carries client_id: the provider matches the code against it.
        Assert.Equal(ClientId, form["client_id"]);
    }

    [Fact]
    public async Task A_provider_refusal_carries_its_words_and_the_status()
    {
        var handler = TokenHandler(
            HttpStatusCode.BadRequest,
            """{"error":"invalid_grant","error_description":"the code is not valid"}""");
        using var client = BuildClient(handler);

        var refusal = await Assert.ThrowsAsync<ExchangeException>(
            () => client.ExchangeAsync("code-used", "verifier-1"));

        Assert.Equal("invalid_grant", refusal.OAuthError);
        Assert.Equal("the code is not valid", refusal.Description);
        Assert.Equal(400, refusal.Status);
    }

    [Fact]
    public async Task The_tls_client_auth_501_is_surfaced_as_the_exchange_error_it_is()
    {
        // What the provider answers a tls_client_auth client today; the
        // library surfaces it verbatim rather than pretending the method works.
        var handler = TokenHandler(
            HttpStatusCode.NotImplemented,
            """{"error":"invalid_request","error_description":"tls_client_auth is not implemented at this endpoint yet; use private_key_jwt or client_secret_basic"}""");
        using var client = BuildClient(handler);

        var refusal = await Assert.ThrowsAsync<ExchangeException>(
            () => client.ExchangeAsync("code-1", "verifier-1"));

        Assert.Equal(501, refusal.Status);
        Assert.Equal("invalid_request", refusal.OAuthError);
        Assert.Contains("not implemented at this endpoint yet", refusal.Description);
    }

    [Fact]
    public async Task A_non_json_error_still_names_the_status()
    {
        var handler = TokenHandler(HttpStatusCode.BadGateway, "upstream fell over");
        using var client = BuildClient(handler);

        var refusal = await Assert.ThrowsAsync<ExchangeException>(
            () => client.ExchangeAsync("code-1", "verifier-1"));

        Assert.Equal("server_error", refusal.OAuthError);
        Assert.Equal("the provider answered 502", refusal.Description);
    }

    [Fact]
    public async Task A_success_without_an_id_token_is_an_error()
    {
        var handler = TokenHandler(HttpStatusCode.OK, """{"access_token":"at-1"}""");
        using var client = BuildClient(handler);

        var refusal = await Assert.ThrowsAsync<ExchangeException>(
            () => client.ExchangeAsync("code-1", "verifier-1"));

        Assert.Equal("server_error", refusal.OAuthError);
        Assert.Equal("no id_token in the token response", refusal.Description);
    }

    [Fact]
    public async Task Missing_arguments_are_refused_before_any_request()
    {
        var handler = TokenHandler();
        using var client = BuildClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.ExchangeAsync("", "verifier-1"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.ExchangeAsync("code-1", " "));
        Assert.Empty(handler.Calls);
    }
}
