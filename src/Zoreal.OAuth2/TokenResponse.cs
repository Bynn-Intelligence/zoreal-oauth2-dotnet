namespace Zoreal.OAuth2;

/// <summary>
/// The token endpoint's answer. The access token lives ten minutes; read
/// /userinfo while handling the login rather than storing it for later.
/// </summary>
public sealed record TokenResponse(
    string IdToken,
    string? AccessToken,
    string? TokenType,
    long? ExpiresIn,
    string? Scope)
{
    // Records print their properties; two of these are bearer material.
    public override string ToString() => $"TokenResponse(tokens hidden, scope: {Scope})";
}
