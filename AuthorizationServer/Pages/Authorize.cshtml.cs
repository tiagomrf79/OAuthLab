using AuthorizationServer.Data;
using AuthorizationServer.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthorizationServer.Pages;

public class AuthorizeModel(InMemoryStore store) : PageModel
{
    public string ReqId { get; set; } = "";
    public string ClientName { get; set; } = "";
    public List<string> RequestedScopes { get; set; } = [];

    public IActionResult OnGet(string response_type, string client_id, string redirect_uri, string? scope, string? state)
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            var returnUrl = UriHelper.BuildRelative(Request.PathBase, Request.Path, Request.QueryString);
            return RedirectToPage("/Login", new { returnUrl });
        }

        var client = store.FindClient(client_id);
        if (client is null)
        {
            return BadRequest("Unknown client.");
        }

        if (!client.RedirectUris.Contains(redirect_uri))
        {
            return BadRequest("Invalid redirect URI.");
        }

        if (!client.ResponseTypes.Contains(response_type))
        {
            return Redirect(OAuthRedirect.Build(redirect_uri, new() { ["error"] = "unauthorized_client" }, state));
        }

        var allowedScopes = (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(client.AllowedScopes).ToArray();
        if (allowedScopes.Length == 0)
        {
            return Redirect(OAuthRedirect.Build(redirect_uri, new() { ["error"] = "invalid_scope" }, state));
        }

        var reqId = InMemoryStore.GenerateToken(8);
        store.PendingAuthorizationRequests[reqId] = new PendingAuthorizationRequest
        {
            ResponseType = response_type,
            ClientId = client_id,
            RedirectUri = redirect_uri,
            Scope = scope ?? "",
            State = state ?? "",
        };

        ReqId = reqId;
        ClientName = client.Name;
        RequestedScopes = [.. allowedScopes];
        return Page();
    }
}
