namespace AuthorizationServer.Models;

public class AccessToken //TBR
{
    public required string Token { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string Scope { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }

    // Ties every token that came out of one authorization together — the first access token and
    // refresh token from a code/password grant, plus every access token later minted from that
    // refresh token. Revoking the refresh token revokes the whole grant (RFC 7009 §2.1).
    public required string GrantId { get; init; }
}

public class RefreshToken //TBR
{
    public required string Token { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string Scope { get; init; }

    // See AccessToken.GrantId.
    public required string GrantId { get; init; }
}
