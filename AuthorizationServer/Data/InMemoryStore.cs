using System.Collections.Concurrent;
using System.Security.Cryptography;
using AuthorizationServer.Models;

namespace AuthorizationServer.Data;

// Everything here is in-memory and reset on restart — this is a teaching sandbox
// modeled after the "OAuth 2 in Action" reference authorization server, not production storage.
public class InMemoryStore
{
    public List<Client> Clients { get; } =
    [
        new Client
        {
            ClientId = "confidential-client",
            ClientSecret = "confidential-client-secret",
            Name = "Confidential Client",
            RedirectUris = ["http://localhost:5000/callback"],
            AllowedScopes = ["read", "write", "delete"],
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
        },
        new Client
        {
            // Static secret for now, same as ConfidentialClient — a real installed app can't
            // keep this confidential (it ships inside the package), which is why this is slated
            // to move to dynamic client registration and then PKCE. Redirect URI is a custom
            // scheme the OS hands back to the app, not a web address — see
            // NativeClient/Platforms/Android/WebAuthenticationCallbackActivity.cs.
            ClientId = "native-client",
            ClientSecret = "native-client-secret",
            Name = "Native Client",
            RedirectUris = ["nativeclient://callback"],
            AllowedScopes = ["read", "write", "delete"],
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
        Clients.FirstOrDefault(c => c.ClientId == clientId);

    public OAuthUser? FindUser(string username, string password) =>
        Users.FirstOrDefault(u => u.Username == username && u.Password == password);

    public static string GenerateToken(int byteLength = 32) =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(byteLength)).ToLowerInvariant();
}
