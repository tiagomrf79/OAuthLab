using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProtectedResource;

// Validates the RFC 9068 JWT access tokens minted by AuthorizationServer's AccessTokenIssuer, entirely
// locally — the only call back to the authorization server is fetching its public signing keys
// (JWKS). Hand-rolled to mirror the issuer so each check is visible; a real resource server would
// use a vetted library (e.g. Microsoft.AspNetCore.Authentication.JwtBearer) instead.
//
// Since nothing is looked up per token, a token stays valid here until it expires even if the
// authorization server has forgotten it — see IntrospectionAccessTokenValidator for the alternative.
public sealed class JwtAccessTokenValidator(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<JwtAccessTokenValidator> logger)
    : IAccessTokenValidator
{
    // Tolerates small clock drift between this server and the authorization server.
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    // An unknown kid triggers a JWKS refetch (that's how a key rotation — or an authorization server
    // restart, which generates a new key — gets picked up), but no more often than this, so a flood
    // of tokens with made-up kids can't be turned into a flood of requests to the authorization server.
    private static readonly TimeSpan MinRefreshInterval = TimeSpan.FromSeconds(10);

    private readonly string issuer = configuration["AccessToken:Issuer"] ?? throw new InvalidOperationException("AccessToken:Issuer is not configured.");
    private readonly string audience = configuration["AccessToken:Audience"] ?? throw new InvalidOperationException("AccessToken:Audience is not configured.");
    private readonly string jwksUri = configuration["AccessToken:JwksUri"] ?? throw new InvalidOperationException("AccessToken:JwksUri is not configured.");

    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private Dictionary<string, RSA> keys = [];
    private DateTimeOffset lastRefresh = DateTimeOffset.MinValue;

    public async Task<ValidatedAccessToken?> ValidateAsync(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        JsonElement header;
        JsonElement payload;
        byte[] signature;
        try
        {
            header = JsonSerializer.Deserialize<JsonElement>(Base64Url.DecodeFromChars(parts[0]));
            payload = JsonSerializer.Deserialize<JsonElement>(Base64Url.DecodeFromChars(parts[1]));
            signature = Base64Url.DecodeFromChars(parts[2]);
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return null;
        }

        // The algorithm is pinned rather than taken from the header — trusting the token's own "alg"
        // is the classic JWT hole ("none", or HS256 keyed with the RSA public key).
        if (GetString(header, "alg") != "RS256")
        {
            return null;
        }

        // RFC 9068 §4: reject anything not typed as an access token, e.g. an ID token signed by the
        // same key.
        if (GetString(header, "typ") is not ("at+jwt" or "application/at+jwt"))
        {
            return null;
        }

        var kid = GetString(header, "kid");
        if (kid is null || await GetKeyAsync(kid) is not { } key)
        {
            return null;
        }

        if (!key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return null;
        }

        // Only now that the signature holds are the claims worth reading at all.
        if (GetString(payload, "iss") != issuer || !HasAudience(payload, audience))
        {
            return null;
        }

        if (!payload.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number
            || DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()) < DateTimeOffset.UtcNow - ClockSkew)
        {
            return null;
        }

        var subject = GetString(payload, "sub");
        var clientId = GetString(payload, "client_id");
        if (subject is null || clientId is null)
        {
            return null;
        }

        var scopes = (GetString(payload, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new ValidatedAccessToken(subject, clientId, scopes);
    }

    private async Task<RSA?> GetKeyAsync(string kid)
    {
        if (keys.TryGetValue(kid, out var key))
        {
            return key;
        }

        await refreshLock.WaitAsync();
        try
        {
            // Another request may have refreshed while this one waited for the lock.
            if (keys.TryGetValue(kid, out key))
            {
                return key;
            }

            if (DateTimeOffset.UtcNow - lastRefresh < MinRefreshInterval)
            {
                return null;
            }

            lastRefresh = DateTimeOffset.UtcNow;
            keys = await FetchKeysAsync();
            return keys.GetValueOrDefault(kid);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or FormatException)
        {
            // Keys already cached keep working; only tokens needing a new key fail until it's back.
            logger.LogWarning(ex, "Could not fetch signing keys from {JwksUri}.", jwksUri);
            return null;
        }
        finally
        {
            refreshLock.Release();
        }
    }

    private async Task<Dictionary<string, RSA>> FetchKeysAsync()
    {
        var jwks = await httpClientFactory.CreateClient().GetFromJsonAsync<JsonElement>(jwksUri);
        var fetched = new Dictionary<string, RSA>();

        foreach (var jwk in jwks.GetProperty("keys").EnumerateArray())
        {
            if (GetString(jwk, "kty") != "RSA" || GetString(jwk, "kid") is not { } kid
                || GetString(jwk, "n") is not { } n || GetString(jwk, "e") is not { } e)
            {
                continue;
            }

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = Base64Url.DecodeFromChars(n),
                Exponent = Base64Url.DecodeFromChars(e),
            });
            fetched[kid] = rsa;
        }

        return fetched;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    // RFC 7519 §4.1.3: "aud" may be a single string or an array of strings.
    private static bool HasAudience(JsonElement payload, string expected) =>
        payload.TryGetProperty("aud", out var aud) && aud.ValueKind switch
        {
            JsonValueKind.String => aud.GetString() == expected,
            JsonValueKind.Array => aud.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && a.GetString() == expected),
            _ => false,
        };
}
