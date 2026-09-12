namespace AuthorizationServer.Models;

public class Client
{
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string Name { get; init; }
    public required string[] RedirectUris { get; init; }
    public required string[] AllowedScopes { get; init; }
}
