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

    // Validation here only covers what we can't safely bounce back to the client for
    // (an unknown client, or a redirect_uri it never registered) — everything else, including
    // whether response_type/scope are even valid, is deferred to /approve, same as the book.
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
            return BadRequest("Unknown client_id.");
        }

        if (!client.RedirectUris.Contains(redirect_uri))
        {
            return BadRequest("redirect_uri does not match a registered value for this client.");
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
        RequestedScopes = [.. (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(client.AllowedScopes)];
        return Page();
    }
}
