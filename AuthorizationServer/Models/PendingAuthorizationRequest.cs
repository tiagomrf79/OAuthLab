namespace AuthorizationServer.Models;

// The raw /authorize query, stashed server-side between the consent screen (GET /authorize)
// and the decision (POST /approve).
public class PendingAuthorizationRequest
{
    public required string ResponseType { get; init; } //TBR: remove?
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string State { get; init; }

    // RFC 7636 — null when the client didn't use PKCE for this request.
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
}
