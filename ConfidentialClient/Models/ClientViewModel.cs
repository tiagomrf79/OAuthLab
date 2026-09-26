namespace ConfidentialClient.Models;

public record ClientViewModel
{
    public required OAuthClientConfig Config { get; init; }
    public string? State { get; init; }
    public string? Code { get; init; }
    public string? CodeVerifier { get; init; }
    public string? CodeChallenge { get; init; }
    public string? AccessToken { get; init; }
    public string? TokenType { get; init; }
    public string? ExpiresIn { get; init; }
    public string? RefreshToken { get; init; }
    public string? Scope { get; init; }
    public string? Error { get; init; }
    public List<LogEntry> Logs { get; init; } = [];
}
