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
            AllowedScopes = ["foo"],
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
