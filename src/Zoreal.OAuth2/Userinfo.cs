using System.Text.Json;

namespace Zoreal.OAuth2;

/// <summary>
/// The /userinfo claims, typed. Which of these are present is decided by the
/// scope your client was granted: email needs the email scope, the name trio
/// needs profile.name, and so on. Every accessor is null when its claim was
/// not served.
/// </summary>
public sealed class Userinfo
{
    /// <summary>No claims at all: what a login without an access token gets.</summary>
    public static readonly Userinfo Empty = new(new Dictionary<string, JsonElement>());

    /// <summary>Every claim as served, for anything the accessors do not cover.</summary>
    public IReadOnlyDictionary<string, JsonElement> Claims { get; }

    internal Userinfo(IReadOnlyDictionary<string, JsonElement> claims) => Claims = claims;

    /// <summary>
    /// email scope. The address the holder verified with ZOREAL, not one
    /// typed into anything your page rendered.
    /// </summary>
    public string? Email => StringClaim("email");

    /// <summary>email scope. True only when the claim is present and true.</summary>
    public bool EmailVerified =>
        Claims.TryGetValue("email_verified", out var value) && value.ValueKind == JsonValueKind.True;

    /// <summary>profile.name scope.</summary>
    public string? Name => StringClaim("name");

    /// <summary>profile.name scope.</summary>
    public string? GivenName => StringClaim("given_name");

    /// <summary>profile.name scope.</summary>
    public string? FamilyName => StringClaim("family_name");

    /// <summary>profile.birthdate scope. ISO 8601.</summary>
    public string? Birthdate => StringClaim("birthdate");

    /// <summary>profile.document scope.</summary>
    public string? DocumentType => StringClaim("document_type");

    /// <summary>profile.document scope.</summary>
    public string? DocumentNumber => StringClaim("document_number");

    /// <summary>profile.document scope. ISO 3166-1 alpha-3.</summary>
    public string? IssuingCountry => StringClaim("issuing_country");

    /// <summary>profile.document scope. ISO 8601.</summary>
    public string? DocumentExpiresOn => StringClaim("document_expires_on");

    /// <summary>
    /// profile.portrait scope. The scope is registrable, but the provider
    /// does not serve the portrait claim yet, so this stays null today; the
    /// accessor exists so the shape is ready when it ships.
    /// </summary>
    public string? Portrait => StringClaim("portrait");

    private string? StringClaim(string name) =>
        Claims.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
