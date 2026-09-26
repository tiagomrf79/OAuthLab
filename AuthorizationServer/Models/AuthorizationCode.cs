namespace AuthorizationServer.Models;

public class AuthorizationCode
{
    public required string Code { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string Subject { get; init; } //TBR: remove?
    public required DateTimeOffset ExpiresAt { get; init; } //TBR: remove?

    // Carried over from the authorization request. When set, /token requires a matching
    // code_verifier; when null, /token rejects any code_verifier that is sent.
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
}
