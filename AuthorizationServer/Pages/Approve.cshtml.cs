using System.Security.Claims;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthorizationServer.Pages;

public class ApproveModel(InMemoryStore store) : PageModel
{
    public IActionResult OnPost(string reqid, string action, string[]? scope)
    {
        if (!store.PendingAuthorizationRequests.TryRemove(reqid, out var pending))
        {
            return BadRequest("No matching authorization request.");
        }

        if (action != "approve")
        {
            return Redirect(OAuthRedirect.Build(pending.RedirectUri, new() { ["error"] = "access_denied" }, pending.State));
        }

        if (pending.ResponseType != "code")
        {
            return Redirect(OAuthRedirect.Build(pending.RedirectUri, new() { ["error"] = "unsupported_response_type" }, pending.State));
        }

        var client = store.FindClient(pending.ClientId);
        if (client is null)
        {
            return BadRequest("Unknown client.");
        }

        var grantedScopes = (scope ?? []).Intersect(client.AllowedScopes).ToArray();
        if (grantedScopes.Length == 0)
        {
            return Redirect(OAuthRedirect.Build(pending.RedirectUri, new() { ["error"] = "invalid_scope" }, pending.State));
        }

        var subject = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var code = InMemoryStore.GenerateToken(16);
        store.AuthorizationCodes[code] = new AuthorizationCode
        {
            Code = code,
            ClientId = pending.ClientId,
            RedirectUri = pending.RedirectUri,
            Scope = string.Join(' ', grantedScopes),
            Subject = subject,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(180),
        };

        return Redirect(OAuthRedirect.Build(pending.RedirectUri, new() { ["code"] = code }, pending.State));
    }
}
