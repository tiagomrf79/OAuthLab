using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace ProtectedResource;

// RFC 7662 token introspection: instead of reading the token, hand it back to the authorization
// server and ask whether it's active. Used for reference tokens, which are random strings with
// nothing in them to read, and for minimal JWTs once they've passed local verification.
//
// The trade-off against JwtAccessTokenValidator: one network round trip per request (nothing is
// cached, so every call shows up at /introspect), in exchange for an answer that reflects the
// authorization server's current state rather than a snapshot taken when the token was minted.
public sealed class IntrospectionAccessTokenValidator(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<IntrospectionAccessTokenValidator> logger)
    : IAccessTokenValidator
{
    private readonly string introspectionEndpoint = configuration["AccessToken:IntrospectionEndpoint"] ?? throw new InvalidOperationException("AccessToken:IntrospectionEndpoint is not configured.");
    private readonly string audience = configuration["AccessToken:Audience"] ?? throw new InvalidOperationException("AccessToken:Audience is not configured.");

    // This resource server's own credentials at /introspect — not a client's; see the authorization
    // server's InMemoryStore.ResourceServers.
    private readonly AuthenticationHeaderValue credentials = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(
        $"{Uri.EscapeDataString(configuration["AccessToken:ResourceId"] ?? throw new InvalidOperationException("AccessToken:ResourceId is not configured."))}:" +
        $"{Uri.EscapeDataString(configuration["AccessToken:ResourceSecret"] ?? throw new InvalidOperationException("AccessToken:ResourceSecret is not configured."))}")));

    public async Task<ValidatedAccessToken?> ValidateAsync(string token)
    {
        JsonElement response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, introspectionEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["token"] = token,
                    ["token_type_hint"] = "access_token",
                }),
            };
            request.Headers.Authorization = credentials;

            using var httpResponse = await httpClientFactory.CreateClient().SendAsync(request);
            httpResponse.EnsureSuccessStatusCode();
            response = await httpResponse.Content.ReadFromJsonAsync<JsonElement>();
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException)
        {
            // Fails closed: if the authorization server can't vouch for the token, it isn't accepted.
            logger.LogWarning(ex, "Token introspection at {IntrospectionEndpoint} failed.", introspectionEndpoint);
            return null;
        }

        if (response.ValueKind != JsonValueKind.Object
            || !response.TryGetProperty("active", out var active) || active.ValueKind != JsonValueKind.True)
        {
            return null;
        }

        // §2.2 makes everything but "active" optional, so a token that's active but meant for some
        // other resource server still has to be turned away here.
        if (response.TryGetProperty("aud", out var aud) && !HasAudience(aud, audience))
        {
            return null;
        }

        var subject = GetString(response, "sub");
        var clientId = GetString(response, "client_id");
        if (subject is null || clientId is null)
        {
            return null;
        }

        var scopes = (GetString(response, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new ValidatedAccessToken(subject, clientId, scopes);
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool HasAudience(JsonElement aud, string expected) => aud.ValueKind switch
    {
        JsonValueKind.String => aud.GetString() == expected,
        JsonValueKind.Array => aud.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && a.GetString() == expected),
        _ => false,
    };
}
