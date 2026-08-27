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

## Assurance levels — `Acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim — *Authentication Context Class
Reference*. It is a single string in the ID token that says **how strongly this
particular login was authenticated**. Every ZOREAL login carries one, surfaced
as `login.Acr`, and it is the difference between "someone who once enrolled this
identity is behind this request" and "a live human, verified to be the right
one, is behind this request right now".

It answers a question the `Sub` cannot. `Sub` tells you *who* (a stable,
pairwise identifier for this person at your site). `Acr` tells you *how sure
ZOREAL is that the person is really there for this login*. A stolen, unlocked
phone can still produce a `Sub`; it cannot produce a fresh `zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested — a login that could only reach a weaker level says so honestly rather
than claiming the level you asked for.

| `Acr` | What the holder did | `Amr` | What it proves | What it does **not** prove |
|---|---|---|---|---|
| `zoreal.session` | Nothing — a returning holder at a site they have used before, resumed silently from an existing ZOREAL session, no phone interaction | `[]` | Continuity: the same browser/session ZOREAL already knew | That the holder is present, or even awake |
| `zoreal.device` | Approved the login on their enrolled phone: a signature from a key in the phone's secure element, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a live face was captured for *this* login — an unlocked phone in the wrong hands still signs |
| `zoreal.live` | All of the above **plus** a fresh face capture this login: a flash-plus-zoom video scored for presentation attacks and screen replay (moire), matched 1:1 against the government document read at enrolment | `["hwk","face","user"]` | A live, real, unique human, verified to be the enrolled person, **at the moment of this login** | — (this is the strongest level) |

`Amr` (*Authentication Methods References*, `login.Amr`) is the companion claim
listing the factors used: `hwk` a hardware key, `user` a user-presence/unlock
gesture, `face` a face biometric. `zoreal.live` is exactly `zoreal.device` with
`face` added, because a live login is a device approval with a capture on top.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks
for nothing still requires the enrolled phone and a local unlock. Silence has to
be explicitly asked for (`prompt=none`), and it succeeds only for a returning
holder at a site whose consent they have already given.

### When to require which

- **`zoreal.session`** — you never *require* this; it is what a returning holder
  gets for a low-stakes convenience re-auth when they ask for the silent path.
- **`zoreal.device`** (the default) — a forum, a community, a normal account
  login. Possession of the enrolled phone plus a local unlock is a high bar
  already; most sites want exactly this and should pass no `acr` at all.
- **`zoreal.live`** — a bank onboarding, a high-value transaction, an age-gated
  purchase, a first login, a "confirm it is really you" step before a sensitive
  action. Anywhere a *fresh, unforgeable proof of the live, right human* is worth
  the few seconds a face capture costs.

### Requesting versus verifying — the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the
second is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: 'zoreal.live'`. This is what makes the holder's ZOREAL ID app
   run the face capture before it will approve. It is **advisory** — it shapes
   what the holder is asked to do, nothing more. A browser is
   attacker-controlled; a value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing the `acr` argument to
   `AuthenticateAsync`. The signed `acr` claim in the ID token — minted by
   ZOREAL, not by the browser — is the proof.

```csharp
var login = await zoreal.AuthenticateAsync(
    body.Code,
    body.CodeVerifier,
    body.Nonce,
    acr: "zoreal.live");    // throws VerificationException unless the signed token says so

login.Acr;                            // "zoreal.live" — what actually happened
login.IsLive;                         // convenience: Acr == "zoreal.live"
login.SatisfiesAcr("zoreal.device");  // true (live is stronger than device)
```

**An RP that requests `zoreal.live` on the wire but never passes the `acr`
argument here has checked nothing** — it has only asked the holder nicely and
then trusted a value it never validated.

### How the check behaves

Verification satisfies **upward**: `zoreal.session < zoreal.device <
zoreal.live` (the ordering is `ZorealOAuth2Client.AcrOrder`), so a requirement
of `zoreal.device` accepts a `zoreal.live` token — the holder gave you *more*
assurance than you demanded. A token whose `acr` is below the requirement,
missing entirely, or outside the vocabulary is refused with
`VerificationException`. An unknown *required* value — a typo like
`"zoreal.liveness"` — throws `ConfigurationException` instead, because that is a
bug in your code, not a bad token, and failing every login silently is worse
than saying so.

If you prefer to branch rather than throw, omit the `acr` argument and inspect
the result with `SatisfiesAcr`:

```csharp
var login = await zoreal.AuthenticateAsync(body.Code, body.CodeVerifier, body.Nonce);
if (!login.SatisfiesAcr("zoreal.live"))
{
    // step the user up, or refuse the sensitive action
}
```

`SatisfiesAcr` reads the same ordering, so an unknown *actual* or *required*
value satisfies nothing (it returns `false` rather than throwing — the throwing
path is the required-argument one on `AuthenticateAsync`).

### `Acr` versus the assurance block

Do not confuse `Acr` with `login.Assurance`. `Acr` grades *this login event*.
The **assurance block** (`login.Assurance`, the `zoreal` claim) describes the
*identity behind it* — how the person was verified at enrolment: the uniqueness
basis, the verification month, whether chip liveness was proven
(`chip_liveness_proven`), the trust tier (`trust_tier`), and the device's key
protection. One is about now; the other is about who they are. A high-value flow
usually wants both: `acr: "zoreal.live"` for presence, and the assurance block
for the strength of the underlying identity proofing.

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
