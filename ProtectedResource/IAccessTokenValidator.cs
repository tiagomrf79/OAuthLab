namespace ProtectedResource;

// Decides whether a bearer token is good and what it grants. DispatchingAccessTokenValidator is the
// one the endpoints use; it combines the two underlying checks depending on the kind of token:
//   JwtAccessTokenValidator           — verify a JWT's signature and claims locally (RFC 9068).
//   IntrospectionAccessTokenValidator — ask the authorization server (RFC 7662).
public interface IAccessTokenValidator
{
    // Null means the token must be refused as invalid_token; the reason is deliberately not surfaced.
    Task<ValidatedAccessToken?> ValidateAsync(string token);
}

public record ValidatedAccessToken(string Subject, string ClientId, string[] Scopes);
