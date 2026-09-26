using System.Text.Json.Serialization;

namespace AuthorizationServer.Models;

// RFC 7591 §2 client metadata — trimmed to the fields this lab's clients actually send.
public class ClientRegistrationRequest
{
    [JsonPropertyName("redirect_uris")]
    public string[]? RedirectUris { get; set; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; }

    [JsonPropertyName("grant_types")]
    public string[]? GrantTypes { get; set; }

    [JsonPropertyName("response_types")]
    public string[]? ResponseTypes { get; set; }

    // Not part of RFC 7591 — a lab-specific extension. Defaults to true for "none" clients (which
    // can't opt out) and false otherwise.
    [JsonPropertyName("require_pkce")]
    public bool? RequirePkce { get; set; }

    // Also a lab-specific extension: "jwt" (the default), "jwt-minimal" or "reference". See
    // Client.AccessTokenFormat.
    [JsonPropertyName("access_token_format")]
    public string? AccessTokenFormat { get; set; }
}
