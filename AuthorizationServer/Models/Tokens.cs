namespace AuthorizationServer.Models;

public class AccessToken //TBR
{
    public required string Token { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string Scope { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}

public class RefreshToken //TBR
{
    public required string Token { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string Scope { get; init; }
}
