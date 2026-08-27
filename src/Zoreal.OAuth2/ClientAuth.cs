using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Zoreal.OAuth2;

/// <summary>
/// How the client authenticates at the token endpoint: one case per
/// registered token_endpoint_auth_method. Pick the case that matches what
/// the dashboard shows for your client; the provider verifies the code was
/// issued to your client_id either way, so the method here has to be the one
/// you registered.
/// </summary>
public abstract record ClientAuth
{
    private ClientAuth() { }

    /// <summary>
    /// A public client: no secret, no key. The token request carries the
    /// client_id alone and PKCE is the only proof, which is why a public
    /// client can only ever have been granted Tier A scopes.
    /// </summary>
    public sealed record None : ClientAuth
    {
        public static readonly None Instance = new();

        public override string ToString() => "ClientAuth.None";
    }

    /// <summary>
    /// A confidential client with a shared secret. The secret travels as HTTP
    /// Basic (client_id as the user, the secret as the password); the form
    /// still carries client_id because the provider matches the code against
    /// it. The secret is shown once at registration and this library holds it
    /// only in memory, never in an error message.
    /// </summary>
    public sealed record ClientSecretBasic : ClientAuth
    {
        public string ClientSecret { get; }

        public ClientSecretBasic(string clientSecret)
        {
            if (string.IsNullOrWhiteSpace(clientSecret))
                throw new ConfigurationException("client_secret_basic needs a client secret");
            ClientSecret = clientSecret;
        }

        // Records print their properties; this one's property is a secret.
        public override string ToString() => "ClientAuth.ClientSecretBasic(secret hidden)";
    }

    /// <summary>
    /// A confidential client holding a private key (RFC 7523). The library
    /// builds and signs a fresh client_assertion for every token request:
    /// iss and sub are the client_id, aud is the token endpoint, the lifetime
    /// stays inside the provider's 60-second maximum, and the jti is random
    /// per assertion because the provider enforces single use. The provider
    /// verifies against the public JWKS you registered (or the key ZOREAL
    /// certified); the private key never leaves this process.
    /// </summary>
    public sealed record PrivateKeyJwt : ClientAuth
    {
        internal SigningCredentials SigningCredentials { get; }

        /// <summary>"ES256" for a P-256 key, "RS256" for an RSA key.</summary>
        public string Algorithm { get; }

        private PrivateKeyJwt(SigningCredentials signingCredentials, string algorithm)
        {
            SigningCredentials = signingCredentials;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Reads a PEM private key: SEC1 ("EC PRIVATE KEY"), PKCS#1
        /// ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY"). A P-256 key signs
        /// ES256, which is the provider's preferred algorithm and the one its
        /// certified-key path uses; an RSA key (2048 bits or more) signs
        /// RS256. Pass the kid your registered JWKS carries so the provider
        /// picks the right key without trying them all.
        /// </summary>
        public static PrivateKeyJwt FromPem(string privateKeyPem, string? keyId = null)
        {
            if (string.IsNullOrWhiteSpace(privateKeyPem))
                throw new ConfigurationException("private_key_jwt needs a private key");

            if (privateKeyPem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal))
                return FromRsa(ImportRsa(privateKeyPem), keyId);
            if (privateKeyPem.Contains("BEGIN EC PRIVATE KEY", StringComparison.Ordinal))
                return FromEc(ImportEc(privateKeyPem), keyId);

            // PKCS#8 carries either kind behind the same label: try EC first,
            // because it is the preferred algorithm, then RSA.
            try
            {
                return FromEc(ImportEc(privateKeyPem), keyId);
            }
            catch (CryptographicException)
            {
                return FromRsa(ImportRsa(privateKeyPem), keyId);
            }
        }

        /// <summary>
        /// Reads a private key from JWK JSON (kty EC with crv P-256, or kty
        /// RSA). The kid inside the JWK becomes the assertion's kid header.
        /// </summary>
        public static PrivateKeyJwt FromJwk(string privateJwkJson)
        {
            if (string.IsNullOrWhiteSpace(privateJwkJson))
                throw new ConfigurationException("private_key_jwt needs a private key");

            JsonWebKey jwk;
            try
            {
                jwk = new JsonWebKey(privateJwkJson);
            }
            catch (ArgumentException e)
            {
                throw new ConfigurationException("the JWK could not be parsed", e);
            }

            if (!jwk.HasPrivateKey)
                throw new ConfigurationException("the JWK does not carry a private key");

            var algorithm = jwk.Kty switch
            {
                "EC" when jwk.Crv == "P-256" => SecurityAlgorithms.EcdsaSha256,
                "EC" => throw new ConfigurationException(
                    $"private_key_jwt signs ES256 with a P-256 key; this JWK's curve is {jwk.Crv}"),
                "RSA" => SecurityAlgorithms.RsaSha256,
                _ => throw new ConfigurationException(
                    $"unsupported JWK key type {jwk.Kty}; use an EC P-256 or RSA key"),
            };
            return new PrivateKeyJwt(new SigningCredentials(jwk, algorithm), algorithm);
        }

        private static PrivateKeyJwt FromEc(ECDsa key, string? keyId)
        {
            if (key.KeySize != 256)
                throw new ConfigurationException(
                    $"private_key_jwt signs ES256 with a P-256 key; this EC key is {key.KeySize} bits");
            var securityKey = new ECDsaSecurityKey(key) { KeyId = keyId };
            return new PrivateKeyJwt(
                new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
                SecurityAlgorithms.EcdsaSha256);
        }

        private static PrivateKeyJwt FromRsa(RSA key, string? keyId)
        {
            if (key.KeySize < 2048)
                throw new ConfigurationException(
                    $"private_key_jwt needs an RSA key of at least 2048 bits; this key is {key.KeySize}");
            var securityKey = new RsaSecurityKey(key) { KeyId = keyId };
            return new PrivateKeyJwt(
                new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256),
                SecurityAlgorithms.RsaSha256);
        }

        private static ECDsa ImportEc(string pem)
        {
            var key = ECDsa.Create();
            key.ImportFromPem(pem);
            return key;
        }

        private static RSA ImportRsa(string pem)
        {
            var key = RSA.Create();
            key.ImportFromPem(pem);
            return key;
        }

        public override string ToString() => $"ClientAuth.PrivateKeyJwt({Algorithm}, key hidden)";
    }

    /// <summary>
    /// Mutual TLS (RFC 8705): the client certificate plus its private key
    /// travel on the connection itself, configured through
    /// HttpClientHandler.ClientCertificates. Load the pair with
    /// <see cref="X509Certificate2.CreateFromPemFile"/> or from a PFX.
    ///
    /// The method is registrable, and the provider currently answers 501
    /// "not implemented at this endpoint yet" when a tls_client_auth client
    /// exchanges a code: the exchange surfaces that verbatim as an
    /// <see cref="ExchangeException"/> with Status 501 rather than pretending.
    /// Register client_secret_basic or private_key_jwt to log in today.
    /// </summary>
    public sealed record TlsClientAuth : ClientAuth
    {
        public X509Certificate2 ClientCertificate { get; }

        public TlsClientAuth(X509Certificate2 clientCertificate)
        {
            ClientCertificate = clientCertificate
                ?? throw new ConfigurationException("tls_client_auth needs a client certificate");
            if (!clientCertificate.HasPrivateKey)
                throw new ConfigurationException(
                    "tls_client_auth needs the certificate's private key; load the pair with X509Certificate2.CreateFromPemFile or from a PFX");
        }

        public override string ToString() => $"ClientAuth.TlsClientAuth({ClientCertificate.Thumbprint})";
    }
}
