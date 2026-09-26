using System.Collections.Concurrent;
using System.Security.Cryptography;
using AuthorizationServer.Models;

namespace AuthorizationServer.Data;

// Everything here is in-memory and reset on restart — this is a teaching sandbox
// modeled after the "OAuth 2 in Action" reference authorization server, not production storage.
public class InMemoryStore
{
    // Every scope the server knows about — dynamic registration (RFC 7591) intersects a client's
    // requested scope against this rather than trusting whatever the caller asks for.
    public static readonly string[] KnownScopes = ["read", "write", "delete"];

    // The only auth methods and grant/response types this server understands. Dynamic registration
    // rejects anything outside these; the seeded clients below are set to match what they actually
    // do today (confidential-client in particular uses grants beyond what RFC 7591 clients get).
    public static readonly string[] KnownAuthMethods = ["client_secret_basic", "client_secret_post", "none"];
    public static readonly string[] KnownGrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password"];
    public static readonly string[] KnownResponseTypes = ["code", "token"];
    public static readonly string[] KnownAccessTokenFormats = ["jwt", "jwt-minimal", "reference"];

    // Dynamically registered clients (RFC 7591) are restricted to this narrower set — the same
    // restriction the "OAuth 2 in Action" reference registration endpoint applies.
    public static readonly string[] RegistrableGrantTypes = ["authorization_code", "refresh_token"];
    public static readonly string[] RegistrableResponseTypes = ["code"];

    // ConcurrentDictionary rather than a list — /register (RFC 7591) adds clients, and the
    // RFC 7592 management endpoints (GET/PUT/DELETE /register/{client_id}) need to look up,
    // replace, and remove a specific client by id, none of which a bag or list does atomically.
    private static readonly Client[] SeededClients =
    [
        new Client
        {
            ClientId = "confidential-client",
            ClientSecret = "confidential-client-secret",
            Name = "Confidential Client",
            RedirectUris = ["http://localhost:5000/callback"],
            AllowedScopes = ["read", "write", "delete"],
            // Always sends its secret via an Authorization: Basic header (see
            // ConfidentialClient/Controllers/HomeController.cs's BasicAuthHeader), and ConfidentialClient
            // is the only app in this lab that exercises client_credentials/password, so it needs all four.
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password"],
            ResponseTypes = ["code"],
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            // Keeps the classic code flow working as-is; it can still send a code_challenge if it wants.
            RequirePkce = false,
            // Server-to-server calls are where skipping the per-request round trip to /introspect pays off.
            AccessTokenFormat = "jwt",
        },
        new Client
        {
            // Identical to confidential-client except for AccessTokenFormat, so the two token styles
            // can be compared from the same ConfidentialClient pages — just switch the client
            // id/secret in the page's config form.
            ClientId = "confidential-client-reference",
            ClientSecret = "confidential-client-reference-secret",
            Name = "Confidential Client (reference tokens)",
            RedirectUris = ["http://localhost:5000/callback"],
            AllowedScopes = ["read", "write", "delete"],
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password"],
            ResponseTypes = ["code"],
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            RequirePkce = false,
            AccessTokenFormat = "reference",
        },
        new Client
        {
            // The third variant of the same client: a signed JWT that says nothing about who or what
            // it's for, so ProtectedResource verifies it locally and then introspects it anyway.
            ClientId = "confidential-client-jwt-minimal",
            ClientSecret = "confidential-client-jwt-minimal-secret",
            Name = "Confidential Client (minimal JWTs)",
            RedirectUris = ["http://localhost:5000/callback"],
            AllowedScopes = ["read", "write", "delete"],
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password"],
            ResponseTypes = ["code"],
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            RequirePkce = false,
            AccessTokenFormat = "jwt-minimal",
        },
        new Client
        {
            // No secret — PublicClient is browser JS and can't keep one confidential. Each flow has
            // its own page and redirect URI on Vite's default dev port (5173) — update these (and
            // PublicClient's .env) if that changes.
            ClientId = "public-client",
            ClientSecret = "",
            Name = "Public Client",
            RedirectUris = ["http://localhost:5173/implicit/", "http://localhost:5173/code-pkce/"],
            AllowedScopes = ["read", "write", "delete"],
            // "token" for the implicit page, "code" for the authorization code + PKCE page. No
            // refresh_token: the refresh grant doesn't rotate tokens yet, and a non-rotating
            // refresh token held in browser JS is exactly what RFC 9700 §4.14 warns against.
            TokenEndpointAuthMethod = "none",
            GrantTypes = ["authorization_code"],
            ResponseTypes = ["token", "code"],
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            // With no secret, PKCE is the only thing tying the code to the app that asked for it.
            RequirePkce = true,
            // Browser JS is where a readable token leaks furthest (devtools, extensions, logs), so
            // this client gets one that reveals nothing — ProtectedResource has to introspect it.
            AccessTokenFormat = "reference",
        },
        // No static entry for NativeClient — it has no baked-in client_id/secret. It registers
        // itself at runtime via POST /register (RFC 7591) and gets added to this dictionary from there.
    ];

    public ConcurrentDictionary<string, Client> Clients { get; } =
        new(SeededClients.ToDictionary(c => c.ClientId));

    // Callers of /introspect (RFC 7662 §2.1 requires the endpoint to authenticate them), matching
    // ProtectedResource's appsettings.json.
    public List<ResourceServer> ResourceServers { get; } =
    [
        new ResourceServer
        {
            ResourceId = "protected-resource",
            ResourceSecret = "protected-resource-secret",
            Name = "Protected Resource",
        },
    ];

    public List<OAuthUser> Users { get; } =
    [
        new OAuthUser
        {
            Subject = "alice",
            Username = "alice",
            Password = "password",
            Name = "Alice",
            Email = "alice@example.com",
        },
    ];

    public ConcurrentDictionary<string, PendingAuthorizationRequest> PendingAuthorizationRequests { get; } = new();
    public ConcurrentDictionary<string, AuthorizationCode> AuthorizationCodes { get; } = new();
    public ConcurrentDictionary<string, AccessToken> AccessTokens { get; } = new();
    public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get; } = new();

    public Client? FindClient(string clientId) =>
        Clients.GetValueOrDefault(clientId);

    public ResourceServer? FindResourceServer(string resourceId) =>
        ResourceServers.FirstOrDefault(r => r.ResourceId == resourceId);

    public OAuthUser? FindUser(string username, string password) =>
        Users.FirstOrDefault(u => u.Username == username && u.Password == password);

    // Removes the refresh token and every access token issued under one grant — what revoking a
    // refresh token means (RFC 7009 §2.1). Removing an entry while enumerating is safe on a
    // ConcurrentDictionary.
    public void RevokeGrant(string grantId)
    {
        foreach (var (token, refreshToken) in RefreshTokens)
        {
            if (refreshToken.GrantId == grantId)
            {
                RefreshTokens.TryRemove(token, out _);
            }
        }

        foreach (var (token, accessToken) in AccessTokens)
        {
            if (accessToken.GrantId == grantId)
            {
                AccessTokens.TryRemove(token, out _);
            }
        }
    }

    public static string GenerateGrantId() => GenerateToken(16);

    public static string GenerateToken(int byteLength = 32) =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(byteLength)).ToLowerInvariant();
}
