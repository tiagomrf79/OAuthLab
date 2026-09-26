namespace ProtectedResource;

// The two ways this resource server can decide whether a bearer token is good — which one runs is
// picked per token by DispatchingAccessTokenValidator, based on what kind of token it is:
//   JwtAccessTokenValidator           — verify a JWT's signature and claims locally (RFC 9068).
//   IntrospectionAccessTokenValidator — ask the authorization server about an opaque token (RFC 7662).
public interface IAccessTokenValidator
{
    // Null means the token must be refused as invalid_token; the reason is deliberately not surfaced.
    Task<ValidatedAccessToken?> ValidateAsync(string token);
}

public record ValidatedAccessToken(string Subject, string ClientId, string[] Scopes);
