using System.Net;
using Xunit;
using static Zoreal.OAuth2.Tests.TestSupport;

namespace Zoreal.OAuth2.Tests;

public sealed class UserinfoTests
{
    [Fact]
    public async Task The_access_token_travels_as_the_bearer_header()
    {
        var handler = new StubHandler((_, _) =>
            Json(HttpStatusCode.OK, """{"sub":"7QK3-9F2M-XR84-B5NP","email":"holder@example.com","email_verified":true}"""));
        using var client = BuildClient(handler);

        var claims = await client.UserinfoAsync("at-1");

        var request = handler.Calls.Single().Request;
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal("at-1", request.Headers.Authorization.Parameter);
        Assert.Equal("holder@example.com", claims["email"].GetString());
    }

    [Fact]
    public async Task A_refusal_surfaces_the_providers_description()
    {
        var handler = new StubHandler((_, _) =>
            Json(HttpStatusCode.Unauthorized, """{"error":"invalid_token","error_description":"the access token is not valid"}"""));
        using var client = BuildClient(handler);

        var refusal = await Assert.ThrowsAsync<UserinfoException>(() => client.UserinfoAsync("at-stale"));

        Assert.Equal("the access token is not valid", refusal.Message);
    }

    [Fact]
    public async Task A_non_json_refusal_still_names_the_status()
    {
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.InternalServerError, "boom"));
        using var client = BuildClient(handler);

        var refusal = await Assert.ThrowsAsync<UserinfoException>(() => client.UserinfoAsync("at-1"));

        Assert.Equal("userinfo answered 500", refusal.Message);
    }

    [Fact]
    public async Task A_blank_access_token_is_refused_before_any_request()
    {
        var handler = new StubHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
        using var client = BuildClient(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.UserinfoAsync(" "));
        Assert.Empty(handler.Calls);
    }
}
