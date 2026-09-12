using System.Security.Claims;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthorizationServer.Pages;

public class ApproveModel(InMemoryStore store) : PageModel
{
    public IActionResult OnPost(string reqid, string action, string[]? scope)
    {
        if (!store.PendingAuthorizationRequests.TryRemove(reqid, out var pending))
        {
            return BadRequest("No matching authorization request — it may have expired.");
        }

        if (action != "approve")
        {
            return Redirect(BuildRedirect(pending.RedirectUri, "access_denied", pending.State));
        }

        if (pending.ResponseType != "code")
        {
            return Redirect(BuildRedirect(pending.RedirectUri, "unsupported_response_type", pending.State));
        }

        var client = store.FindClient(pending.ClientId);
        if (client is null)
        {
            return BadRequest("Unknown client_id.");
        }

        var grantedScopes = (scope ?? []).Intersect(client.AllowedScopes).ToArray();
        if (grantedScopes.Length == 0)
        {
            return Redirect(BuildRedirect(pending.RedirectUri, "invalid_scope", pending.State));
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
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(60),
        };

        var parameters = new Dictionary<string, string?> { ["code"] = code };
        if (!string.IsNullOrEmpty(pending.State))
        {
            parameters["state"] = pending.State;
        }

        return Redirect(QueryHelpers.AddQueryString(pending.RedirectUri, parameters));
    }

    private static string BuildRedirect(string redirectUri, string error, string? state)
    {
        var parameters = new Dictionary<string, string?> { ["error"] = error };
        if (!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        return QueryHelpers.AddQueryString(redirectUri, parameters);
    }
}
