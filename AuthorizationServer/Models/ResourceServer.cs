namespace AuthorizationServer.Models;

// A protected resource allowed to call /introspect (RFC 7662). Deliberately separate from Client:
// a resource server never requests tokens, it only asks about ones presented to it, and a client's
// credentials must not unlock introspection (or a client could probe tokens it doesn't hold).
public class ResourceServer
{
    public required string ResourceId { get; init; }
    public required string ResourceSecret { get; init; }
    public required string Name { get; init; }
}
