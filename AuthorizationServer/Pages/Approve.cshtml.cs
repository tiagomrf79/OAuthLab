using System.Security.Claims;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthorizationServer.Pages;

public class ApproveModel(InMemoryStore store, AccessTokenIssuer tokens) : PageModel
{
    public IActionResult OnPost(string reqid, string action, string[]? scope)
    {
        if (!store.PendingAuthorizationRequests.TryRemove(reqid, out var pending))
        {
            return BadRequest("No matching authorization request.");
        }

        // The implicit grant reports both its token and its errors via the fragment (see
        // OAuthRedirect.BuildFragment); the authorization code grant keeps using the query string.
        string BuildRedirectUrl(Dictionary<string, string?> parameters) =>
            pending.ResponseType == "token"
                ? OAuthRedirect.BuildFragment(pending.RedirectUri, parameters, pending.State)
                : OAuthRedirect.Build(pending.RedirectUri, parameters, pending.State);

        if (action != "approve")
        {
            return Redirect(BuildRedirectUrl(new() { ["error"] = "access_denied" }));
        }

        if (pending.ResponseType != "code" && pending.ResponseType != "token")
        {
            return Redirect(BuildRedirectUrl(new() { ["error"] = "unsupported_response_type" }));
        }

        var client = store.FindClient(pending.ClientId);
        if (client is null)
        {
            return BadRequest("Unknown client.");
        }

        var grantedScopes = (scope ?? []).Intersect(client.AllowedScopes).ToArray();
        if (grantedScopes.Length == 0)
        {
            return Redirect(BuildRedirectUrl(new() { ["error"] = "invalid_scope" }));
        }

        var subject = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var grantedScope = string.Join(' ', grantedScopes);

        if (pending.ResponseType == "token")
        {
            // No refresh token here — RFC 6749 §4.2.2 doesn't define one for the implicit grant,
            // and there'd be no way to redeem it later without a client secret to authenticate with.
            var accessToken = tokens.Issue(client, subject, grantedScope);

            return Redirect(BuildRedirectUrl(new()
            {
                ["access_token"] = accessToken,
                ["token_type"] = "Bearer",
                ["expires_in"] = ((int)AccessTokenIssuer.Lifetime.TotalSeconds).ToString(),
                ["scope"] = grantedScope,
            }));
        }

        var code = InMemoryStore.GenerateToken(16);
        store.AuthorizationCodes[code] = new AuthorizationCode
        {
            Code = code,
            ClientId = pending.ClientId,
            RedirectUri = pending.RedirectUri,
            Scope = grantedScope,
            Subject = subject,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(180),
            CodeChallenge = pending.CodeChallenge,
            CodeChallengeMethod = pending.CodeChallengeMethod,
        };

        return Redirect(BuildRedirectUrl(new() { ["code"] = code }));
    }
}
