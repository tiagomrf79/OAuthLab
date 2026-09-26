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
    public static readonly string[] KnownAuthMethods = ["secret_basic", "secret_post", "none"];
    public static readonly string[] KnownGrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password"];
    public static readonly string[] KnownResponseTypes = ["code", "token"];

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
            // ConfidentialClient/Controllers/HomeController.cs's BasicAuthHeader), and is the only
            // client in this lab that exercises client_credentials/password, so it needs all four.
            TokenEndpointAuthMethod = "secret_basic",
            GrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password"],
            ResponseTypes = ["code"],
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        },
        new Client
        {
            // No secret — this is the implicit-grant public client (PublicClient); it can't keep
            // one confidential in shipped browser JS. Redirect URI matches Vite's default dev
            // port (5173) — update this (and PublicClient's VITE_CLIENT_ID/.env) if that changes.
            ClientId = "public-client",
            ClientSecret = "",
            Name = "Public Client",
            RedirectUris = ["http://localhost:5173/"],
            AllowedScopes = ["read", "write", "delete"],
            // Never calls /token at all — the implicit grant returns its token straight from
            // /authorize — so GrantTypes is empty; "none" reflects that it has no secret to present.
            TokenEndpointAuthMethod = "none",
            GrantTypes = [],
            ResponseTypes = ["token"],
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        },
        // No static entry for NativeClient — it has no baked-in client_id/secret. It registers
        // itself at runtime via POST /register (RFC 7591) and gets added to this dictionary from there.
    ];

    public ConcurrentDictionary<string, Client> Clients { get; } =
        new(SeededClients.ToDictionary(c => c.ClientId));

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

    public OAuthUser? FindUser(string username, string password) =>
        Users.FirstOrDefault(u => u.Username == username && u.Password == password);

    public static string GenerateToken(int byteLength = 32) =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(byteLength)).ToLowerInvariant();
}
