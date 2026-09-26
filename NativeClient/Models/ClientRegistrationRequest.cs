using System.Text.Json.Serialization;

namespace NativeClient.Models;

public class ClientRegistrationRequest
{
    [JsonPropertyName("redirect_uris")]
    public string[] RedirectUris { get; set; } = [];

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
}
