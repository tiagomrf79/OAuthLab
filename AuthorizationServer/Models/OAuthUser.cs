namespace AuthorizationServer.Models;

// Password is plaintext for lab purposes only — never do this outside a learning sandbox.
public class OAuthUser
{
    public required string Subject { get; init; }
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required string Name { get; init; }
    public required string Email { get; init; }
}
