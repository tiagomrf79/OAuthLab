namespace AuthorizationServer.Models;

// The raw /authorize query, stashed server-side between the consent screen (GET /authorize)
// and the decision (POST /approve) — mirrors the book's authServer.js "requests" map, so the
// approval form only ever carries an opaque reqid instead of client-controlled redirect data.
public class PendingAuthorizationRequest
{
    public required string ResponseType { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string State { get; init; }
}
