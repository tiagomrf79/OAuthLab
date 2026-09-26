namespace AuthorizationServer.Models;

public class Client
{
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string Name { get; init; }
    public required string[] RedirectUris { get; init; }
    public required string[] AllowedScopes { get; init; }

    // How this client authenticates at /token: "secret_basic", "secret_post", or "none".
    // Enforced in Program.cs's TryAuthenticateClient — a client must use the exact method it
    // registered with, not just any credentials that happen to match.
    public required string TokenEndpointAuthMethod { get; init; }
    public required string[] GrantTypes { get; init; }
    public required string[] ResponseTypes { get; init; }
    public required long ClientIdIssuedAt { get; init; }

    // RFC 7592 client configuration management — a bearer token, separate from ClientSecret, that
    // authorizes GET/PUT/DELETE on this client's own registration at /register/{client_id}. Null
    // for the statically-seeded clients: they weren't dynamically registered, so nothing can ever
    // present a matching token and they're simply not self-manageable through this API.
    public string? RegistrationAccessToken { get; init; }
}
