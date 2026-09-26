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

    // Whether /authorize rejects a response_type=code request that carries no code_challenge.
    // Clients that don't require PKCE may still send one — /token verifies it whenever the issued
    // code carries a challenge, regardless of this flag.
    public required bool RequirePkce { get; init; }

    // What kind of access token this client gets — the authorization server's call, not the
    // client's (same idea as Duende IdentityServer's per-client AccessTokenType):
    //   "jwt"         — a signed RFC 9068 JWT the resource server can verify on its own.
    //   "jwt-minimal" — a signed JWT with only iss/aud/exp/iat/jti: checkable locally, but who it's
    //                   for and what it grants still has to come from /introspect.
    //   "reference"   — a random string that means nothing without asking /introspect (RFC 7662).
    public required string AccessTokenFormat { get; init; }

    // RFC 7592 client configuration management — a bearer token, separate from ClientSecret, that
    // authorizes GET/PUT/DELETE on this client's own registration at /register/{client_id}. Null
    // for the statically-seeded clients: they weren't dynamically registered, so nothing can ever
    // present a matching token and they're simply not self-manageable through this API.
    public string? RegistrationAccessToken { get; init; }
}
