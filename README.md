# Zoreal.OAuth2

Login with ZOREAL for .NET backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR or app link), and hands your frontend an
authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this package does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
Zoreal.OAuth2 (this package)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react           your frontend: the button, the QR, the polling
```

## Install

```sh
dotnet add package Zoreal.OAuth2
```

.NET 8 or newer. Two dependencies: `Microsoft.IdentityModel.Tokens` and
`System.IdentityModel.Tokens.Jwt`.

## Quick start

Build one client at boot and share it; it is thread-safe.

```csharp
builder.Services.AddSingleton(new ZorealOAuth2Client(new ZorealOAuth2ClientOptions
{
    ClientId = builder.Configuration["Zoreal:ClientId"]!,          // ast_...
    Auth = new ClientAuth.ClientSecretBasic(builder.Configuration["Zoreal:ClientSecret"]!),
    Issuer = builder.Configuration["Zoreal:Issuer"] ?? "https://id.zoreal.com",
}));
```

The endpoint your frontend posts to:

```csharp
app.MapPost("/auth/zoreal", async (ZorealCallback body, ZorealOAuth2Client zoreal) =>
{
    var login = await zoreal.AuthenticateAsync(
        body.Code,
        body.CodeVerifier,   // PKCE is mandatory; the SDK hands it over
        body.Nonce);         // binds the ID token to this login

    login.Sub;               // "TC5X-JN7G-YTSE-6E63" — pairwise, stable for YOUR domain
    login.Acr;               // "zoreal.live" | "zoreal.device" | "zoreal.session"
    login.Assurance;         // uniqueness basis, verification month, chip liveness, trust tier

    var userinfo = await login.UserinfoAsync();   // fetched once, memoized
    userinfo.Email;          // when your client has the email scope
    userinfo.EmailVerified;
    userinfo.Name;           // profile.name scope
});

record ZorealCallback(string Code, string CodeVerifier, string? Nonce);
```

Account matching, the shape that works:

```csharp
var user = await db.Users.FirstOrDefaultAsync(u => u.Provider == "zoreal" && u.Uid == login.Sub);
if (user is null)
{
    var userinfo = await login.UserinfoAsync();
    if (userinfo.EmailVerified)                   // claim, don't collide
        user = await db.Users.FirstOrDefaultAsync(u => u.Email == userinfo.Email);
    user ??= new User { Email = userinfo.Email };
    user.Provider = "zoreal";
    user.Uid = login.Sub;
    await db.SaveChangesAsync();
}
```

## Client authentication

`ClientAuth` has one case per registered `token_endpoint_auth_method`; pass
the one the dashboard shows for your client.

| Case | Who it is for | What travels |
|---|---|---|
| `ClientAuth.None.Instance` | Public clients | `client_id` alone; PKCE is the only proof, which is why a public client only ever holds Tier A scopes |
| `new ClientAuth.ClientSecretBasic(secret)` | Confidential clients with a shared secret | The secret as HTTP Basic, never as a form field |
| `ClientAuth.PrivateKeyJwt.FromPem(pem, kid)` / `.FromJwk(json)` | Confidential clients holding a private key | A fresh RFC 7523 assertion per exchange, signed ES256 (P-256, preferred) or RS256 (RSA); the private key never leaves your process |
| `new ClientAuth.TlsClientAuth(certificate)` | Mutual TLS | The client certificate on the connection, via `HttpClientHandler.ClientCertificates` |

`tls_client_auth` is registrable, and the provider currently answers 501
"not implemented at this endpoint yet" when such a client exchanges a code.
This library configures the transport correctly and surfaces that 501 as the
`ExchangeException` it is, rather than pretending. Register
`client_secret_basic` or `private_key_jwt` to log in today.

The private_key_jwt assertion is built to what the provider enforces: `iss`
and `sub` are your client_id, `aud` is the token endpoint, the lifetime stays
inside the 60-second maximum, and the `jti` is fresh per assertion because
the provider accepts each one exactly once.

## What each call does

| Call | What happens |
|---|---|
| `AuthenticateAsync(code, codeVerifier, nonce?)` | `ExchangeAsync` + `VerifyIdTokenAsync`, returns a `Login` |
| `ExchangeAsync(code, codeVerifier)` | `POST {issuer}/token`, with your configured client authentication |
| `VerifyIdTokenAsync(jwt, nonce?)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `UserinfoAsync(accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login.UserinfoAsync()` | the above, once, memoized; `Userinfo.Empty` when there is no access token |

`Login` reads the verified claims: `Sub`, `Acr`, `Amr`, `Assurance`,
`AgeOver(threshold)` (a `bool?` — null means the threshold is not registered
for your client, which is different from false), `Nationality`, `Claims`,
`IdToken`, `AccessToken`, `Scope`. `Userinfo` types the personal claims:
`Email`, `EmailVerified`, `Name`, `GivenName`, `FamilyName`, `Birthdate`,
`DocumentType`, `DocumentNumber`, `IssuingCountry`, `DocumentExpiresOn`, and
`Portrait` — which stays null today: the profile.portrait scope is
registrable but the provider does not serve the claim yet.

Errors: `ConfigurationException`, `ExchangeException` (carries the provider's
OAuth error code, its description verbatim, and the HTTP status),
`VerificationException`, `UserinfoException`. A returning user matched on
`Sub` can survive a caught `UserinfoException`; a signup that needs the email
cannot. No error message ever carries a token value.

## Things worth knowing before you integrate

- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and — if registered — `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `AuthenticateAsync` alone is not enough for a
  signup.
- **The access token lives 10 minutes.** Read `/userinfo` while handling the
  login; do not store the token for later.
- **`Sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered sector: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration.
- **ES256 only.** The provider signs with nothing else, and this library
  refuses other algorithms rather than negotiating.
- **Always pass the nonce through.** The SDK generates it and gives it to
  your frontend in `onSuccess`; without it your backend cannot tell a
  substituted ID token from the real one.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **Sandbox clients accept localhost origins; production clients do not.**
  Registration lives in the ZOREAL dashboard on the asset's OAuth2 tab; Tier B
  scopes (email, profile.\*) need a confidential client on a verified domain.
- **Match the auth method to what you registered.** `none` for a public
  client, `client_secret_basic` or `private_key_jwt` for a confidential one;
  `private_key_jwt` is the stronger posture because no shared secret exists
  to leak, and it is the method ZOREAL's certified-key path builds on.
  `tls_client_auth` is registrable but not accepted at the token endpoint
  yet, and this library says so instead of faking it.

## Development against a local provider

Point `Issuer` at your provider instance. The issuer value must match the `iss` inside the
tokens exactly — it is compared, not normalized.

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |

## License

MIT.
