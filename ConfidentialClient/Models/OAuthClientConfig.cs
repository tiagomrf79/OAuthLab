namespace ConfidentialClient.Models;

// The effective OAuth settings for this browser session — session overrides (set via the
// Configuration form) win, falling back to appsettings.json defaults. Kept in session, not just
// read at click-time, because the Authorize step navigates away to the AS and back.
public record OAuthClientConfig
{
    public required string AuthorizeEndpoint { get; init; }
    public required string TokenEndpoint { get; init; }
    public required string RevocationEndpoint { get; init; }
    public required string ResourceEndpoint { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string Username { get; init; }
    public required string Password { get; init; }
}
