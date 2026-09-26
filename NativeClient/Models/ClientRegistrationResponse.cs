using System.Text.Json.Serialization;

namespace NativeClient.Models;

public class ClientRegistrationResponse
{
    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    [JsonPropertyName("redirect_uris")]
    public string[]? RedirectUris { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}
