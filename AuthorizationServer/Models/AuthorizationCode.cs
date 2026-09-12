namespace AuthorizationServer.Models;

public class AuthorizationCode
{
    public required string Code { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string Subject { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}
