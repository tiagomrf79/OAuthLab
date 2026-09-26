namespace ProtectedResource;

// The authorization server decides per client which kind of access token it issues, so this
// resource server has to accept all three side by side. The rule is "verify what you can locally,
// ask for what's missing":
//   full JWT     — verified locally, and it carries sub/client_id/scope itself: done, no network call.
//   minimal JWT  — verified locally (so forged, expired or misdirected ones never reach the
//                  authorization server), then introspected for who it's for and what it grants.
//   opaque token — nothing to verify locally; introspected straight away.
//
// The token's shape and contents only pick the path, never grant anything by themselves: a random
// string dressed up with two dots just fails signature verification, and a JWT can only skip
// introspection by carrying a signed scope — without one it has no permissions to hand out.
public sealed class DispatchingAccessTokenValidator(JwtAccessTokenValidator jwt, IntrospectionAccessTokenValidator introspection, ILogger<DispatchingAccessTokenValidator> logger)
    : IAccessTokenValidator
{
    public async Task<ValidatedAccessToken?> ValidateAsync(string token)
    {
        if (token.Count(c => c == '.') != 2)
        {
            logger.LogInformation("Opaque token: introspecting.");
            return await introspection.ValidateAsync(token);
        }

        if (await jwt.VerifyAsync(token) is not { } verified)
        {
            logger.LogInformation("JWT failed local verification: rejected without introspecting.");
            return null;
        }

        if (verified.Access is not null)
        {
            logger.LogInformation("Full JWT verified locally: no introspection needed.");
            return verified.Access;
        }

        logger.LogInformation("Minimal JWT verified locally: introspecting for sub/client_id/scope.");
        return await introspection.ValidateAsync(token);
    }
}
