using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using AuthorizationServer.Data;
using AuthorizationServer.Models;

namespace AuthorizationServer;

// Mints access tokens in whichever format the client is registered for (Client.AccessTokenFormat):
//   "jwt"       — a signed JWT (RFC 7519) following the RFC 9068 access token profile, so a
//                 protected resource can check its signature, expiry, audience and scope locally
//                 instead of having to call back here. Hand-rolled rather than pulled from a JWT
//                 library so the structure (header.payload.signature) stays visible — this is a
//                 teaching sandbox, not production.
//   "reference" — a random string carrying no information at all; the only way to learn what it
//                 grants is to ask /introspect (RFC 7662).
//
// Both kinds are recorded in InMemoryStore.AccessTokens. For a reference token that record *is*
// the token's meaning; for a JWT it's what lets /introspect answer about it (and, later, revoke it).
public sealed class AccessTokenIssuer : IDisposable
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);

    // The default encoder escapes "+" as + — still valid JSON, but "at+jwt" is confusing
    // when the token is pasted into a decoder like jwt.io to inspect it.
    private static readonly JsonSerializerOptions JsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly InMemoryStore store;

    // Exposed so /introspect can report the same iss/aud the JWT itself carries.
    public string Issuer { get; }
    public string Audience { get; }

    // Generated fresh on every start, like the rest of the in-memory state — so tokens issued before
    // a restart stop verifying, the same as opaque tokens vanishing from the store did before.
    private readonly RSA signingKey = RSA.Create(2048);
    private readonly string keyId = InMemoryStore.GenerateToken(8);

    public AccessTokenIssuer(InMemoryStore store, IConfiguration configuration)
    {
        this.store = store;
        Issuer = configuration["AccessToken:Issuer"] ?? throw new InvalidOperationException("AccessToken:Issuer is not configured.");
        Audience = configuration["AccessToken:Audience"] ?? throw new InvalidOperationException("AccessToken:Audience is not configured.");
    }

    public string Issue(Client client, string subject, string scope)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.Add(Lifetime);

        var token = client.AccessTokenFormat == "reference"
            ? InMemoryStore.GenerateToken()
            : CreateJwt(client.ClientId, subject, scope, now, expiresAt);

        store.AccessTokens[token] = new AccessToken
        {
            Token = token,
            ClientId = client.ClientId,
            Subject = subject,
            Scope = scope,
            ExpiresAt = expiresAt,
        };

        return token;
    }

    private string CreateJwt(string clientId, string subject, string scope, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        // RFC 9068 §2.1: "at+jwt" marks this as an access token, so it can't be confused with (or
        // replayed as) an ID token or any other JWT signed by the same key.
        var header = new Dictionary<string, object>
        {
            ["alg"] = "RS256",
            ["typ"] = "at+jwt",
            ["kid"] = keyId,
        };

        // RFC 9068 §2.2 required claims, plus scope (§2.2.3) so the resource can enforce it.
        var payload = new Dictionary<string, object>
        {
            ["iss"] = Issuer,
            ["sub"] = subject,
            ["aud"] = Audience,
            ["client_id"] = clientId,
            ["scope"] = scope,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = InMemoryStore.GenerateToken(16),
        };

        var signingInput = $"{Base64Url(JsonSerializer.SerializeToUtf8Bytes(header, JsonOptions))}.{Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions))}";
        var signature = signingKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url(signature)}";
    }

    // RFC 7517 JWK Set with just the public half of the signing key — served at
    // /.well-known/jwks.json so a protected resource can verify signatures without a shared secret.
    public object GetJsonWebKeySet()
    {
        var parameters = signingKey.ExportParameters(includePrivateParameters: false);
        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = keyId,
                    n = Base64Url(parameters.Modulus!),
                    e = Base64Url(parameters.Exponent!),
                },
            },
        };
    }

    public void Dispose() => signingKey.Dispose();

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
