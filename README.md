# Zoreal.OAuth2

[![NuGet](https://img.shields.io/nuget/v/Zoreal.OAuth2)](https://www.nuget.org/packages/Zoreal.OAuth2) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-oauth2-dotnet/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-oauth2-dotnet/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Bynn-Intelligence/zoreal-oauth2-dotnet/badge)](https://scorecard.dev/viewer/?uri=github.com/Bynn-Intelligence/zoreal-oauth2-dotnet) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

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

## Getting your credentials

Everything `ZorealOAuth2ClientOptions` needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset** — a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users log in to; its token is
   your `ClientId` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and set:
   - the **redirect URIs** and **JavaScript origins** your app uses (requests
     from anything not registered are rejected — this is the core control),
   - the **scopes** the client is allowed to request (see the catalogue below),
   - your **client authentication**: generate a **client secret**
     (`client_secret_basic`), or register a **JWKS** for `private_key_jwt`. A
     public client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown in
   the dashboard) before it can request personal-data scopes or sign users in;
   the verified domain is what your users' `Sub` is pairwise against.

The `ClientId` is public — it ships in your frontend. The client secret is not:
keep it in your server's secret store (the `Zoreal:ClientSecret` above resolves
through the standard configuration providers), never in the browser.

### There is no test-identity sandbox — and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** (enrol in the
ZOREAL ID app) and sign in with it. Mark your asset's environment **sandbox** in
the dashboard while building — a sandbox asset may register `http://localhost`
origins and redirect URIs that a production asset may not — and flip it to
production when you ship. The identities are real either way; only the allowed
origins differ.

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

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans — only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; GDPR Article 9 data) | `/userinfo` | C | confidential client + verified domain — *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client, so the
  no-backend browser button can use it — read it off the `Login` (`Sub`,
  `AgeOver(n)`, `Nationality`). **Tier B and C** are personal data, served only
  from `/userinfo` to a confidential client on a domain you have verified, and
  never placed in a browser token — read them off the `Userinfo`.
- **Age thresholds are a fixed set** — 13, 16, 18, 21, 65 — that you register on
  the asset. `login.AgeOver(n)` returns `null` for a threshold you did not
  register (no claim was minted), which is different from `false`.

## Error reference

`ExchangeAsync` / `AuthenticateAsync` throw `ExchangeException`, which carries
the provider's own `OAuthError` code, its `Description` verbatim, and the HTTP
`Status`. What you will actually see:

| `OAuthError` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent — unknown, expired (60s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed — wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth` (not accepted at `/token` yet) | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError`), so handle them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE/nonce, an unverified sector, an unregistered `redirect_uri`, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume — the expected quiet outcome, not a failure |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app — **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet — offer to try again |

This library's own exceptions all derive from `ZorealOAuth2Exception`, so a
single `catch` can be the backstop while each type below drives the response:

| Type | What it means |
|---|---|
| `ConfigurationException` | You built the client wrong, or asked to verify an acr outside the vocabulary — a bug in your code, not a bad token |
| `ExchangeException` | The provider refused the code exchange; carries `OAuthError`, `Description` and `Status` (the table above) |
| `VerificationException` | The ID token did not verify: signature, `iss`, `aud`, `exp`, `nonce`, or the acr floor |
| `UserinfoException` | The `/userinfo` call failed |

A returning user matched on `Sub` can survive a caught `UserinfoException`; a
signup that needs the email cannot. No error message this library raises ever
carries a token value.

## The assurance block

`login.Assurance` is the ID token's `zoreal` claim — an
`IReadOnlyDictionary<string, JsonElement>?` describing the strength of the
*identity* behind this login (distinct from `Acr`, which grades the *login
event*). It is `null` when the claim is absent. Its keys and their value sets:

| Key | Values | Meaning |
|---|---|---|
| `uniqueness` | `personal_number` \| `document` \| `none` | The anchor the holder is deduplicated on. `personal_number` (a national number from the chip) is strongest; `none` means no reliable anchor |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. Quantised to a month on purpose — a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `true` \| `false` | Whether the passport chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `high` \| `standard` | `high` when `chip_liveness_proven`, else `standard` |
| `key_protection` | `secure_enclave` \| `strongbox` \| `tee` \| `software` | How the holder's device key is protected. `software` means no hardware attestation |

`Acr` grades *this login event*; the assurance block grades *the identity behind
it*. A high-value flow usually wants both — `acr: "zoreal.live"` for fresh
presence, and an assurance-block check for identity strength, e.g. requiring
`uniqueness == "personal_number"` and `trust_tier == "high"`:

```csharp
var login = await zoreal.AuthenticateAsync(
    body.Code, body.CodeVerifier, body.Nonce, acr: "zoreal.live");

var assurance = login.Assurance;
var strongIdentity =
    assurance is not null
    && assurance.TryGetValue("uniqueness", out var uniqueness)
    && uniqueness.GetString() == "personal_number"
    && assurance.TryGetValue("trust_tier", out var tier)
    && tier.GetString() == "high";
```

## A complete example

An ASP.NET Core endpoint, end to end — the shape a real integration takes.

```csharp
// Program.cs — the client, built once and shared (it is thread-safe).
builder.Services.AddSingleton(new ZorealOAuth2Client(new ZorealOAuth2ClientOptions
{
    ClientId = builder.Configuration["Zoreal:ClientId"]!,          // ast_...
    Auth = new ClientAuth.ClientSecretBasic(builder.Configuration["Zoreal:ClientSecret"]!),
    Issuer = builder.Configuration["Zoreal:Issuer"] ?? "https://id.zoreal.com",
}));

// Your frontend's ZorealLogin onSuccess posts { code, codeVerifier, nonce } to
// this route over your own TLS. Protect it with your normal CSRF / same-origin
// controls, exactly as you would any login endpoint — the ZOREAL nonce protects
// the token, not your route.
app.MapPost("/auth/zoreal", async (
    ZorealCallback body,
    ZorealOAuth2Client zoreal,
    AppDb db,
    HttpContext http) =>
{
    Login login;
    try
    {
        login = await zoreal.AuthenticateAsync(
            body.Code,
            body.CodeVerifier,
            body.Nonce);
            // acr: "zoreal.live"  // add for a step-up / high-value login
    }
    catch (ExchangeException)         // a spent code: the login must be restarted
    {
        return Results.Unauthorized();
    }
    catch (VerificationException)     // the token did not verify
    {
        return Results.Unauthorized();
    }

    // Match on Sub first; it is stable for your verified domain.
    var user = await db.Users
        .FirstOrDefaultAsync(u => u.Provider == "zoreal" && u.Uid == login.Sub);
    if (user is null)
    {
        Userinfo info;
        try
        {
            info = await login.UserinfoAsync();
        }
        catch (UserinfoException)
        {
            // Personal data was unreachable. Fatal for a signup that needs the
            // email; a returning user matched on Sub above never reaches here.
            return Results.Unauthorized();
        }

        // Claim an existing account that owns this verified email rather than
        // colliding on the unique index; otherwise create one.
        if (info.EmailVerified)
            user = await db.Users.FirstOrDefaultAsync(u => u.Email == info.Email);
        user ??= new User { Email = info.Email, FullName = info.Name };
        user.Provider = "zoreal";
        user.Uid = login.Sub!;
        db.Users.Update(user);
        await db.SaveChangesAsync();
    }

    // Establish YOUR session on a fresh principal. Sign-in regenerates the auth
    // cookie; treat this as the fixation-defence boundary for your app.
    var identity = new ClaimsIdentity(
        new[] { new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()) },
        CookieAuthenticationDefaults.AuthenticationScheme);
    await http.SignInAsync(new ClaimsPrincipal(identity));
    return Results.Ok(new { ok = true });
});

record ZorealCallback(string Code, string CodeVerifier, string? Nonce);
```

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
- **Always pass the nonce through, and protect your own endpoint too.** The SDK
  generates the nonce and gives it to your frontend in `onSuccess`; passing it
  to `AuthenticateAsync` lets this library confirm the ID token was minted for
  *this* login rather than substituted. Two things it does **not** do: it is not
  your endpoint's CSRF token (protect your `/auth/zoreal` route with ASP.NET
  Core's normal antiforgery / same-origin defence), and PKCE — not the nonce —
  is what proves whoever exchanges the code is whoever started the flow.
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
- **The `Issuer` must match the token's `iss` exactly** — it is compared, not
  normalized. Production is `https://id.zoreal.com`; override `Issuer` only when
  pointing at a non-production provider you were explicitly given.

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
