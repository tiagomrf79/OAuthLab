namespace ProtectedResource;

// The authorization server decides per client whether it issues JWTs or reference tokens, so this
// resource server has to accept both side by side: anything shaped like a JWT (header.payload.signature)
// is verified locally, and everything else is treated as a reference token and introspected.
//
// The shape is only used to pick a path, never trusted: a random string dressed up with two dots
// just fails signature verification, and a real JWT would be judged the same way by /introspect too.
public sealed class DispatchingAccessTokenValidator(JwtAccessTokenValidator jwt, IntrospectionAccessTokenValidator introspection)
    : IAccessTokenValidator
{
    public Task<ValidatedAccessToken?> ValidateAsync(string token) =>
        token.Count(c => c == '.') == 2
            ? jwt.ValidateAsync(token)
            : introspection.ValidateAsync(token);
}
