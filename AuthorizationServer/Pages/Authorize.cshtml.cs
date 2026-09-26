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

    public IActionResult OnGet(string response_type, string client_id, string redirect_uri, string? scope, string? state,
        string? code_challenge, string? code_challenge_method)
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

        // PKCE (RFC 7636) only applies to the code flow — the implicit grant has no /token step to
        // present a verifier at, so any challenge on a response_type=token request is ignored.
        var usePkce = response_type == "code" && !string.IsNullOrEmpty(code_challenge);
        if (response_type == "code")
        {
            if (string.IsNullOrEmpty(code_challenge) && client.RequirePkce)
            {
                return Redirect(OAuthRedirect.Build(redirect_uri, new()
                {
                    ["error"] = "invalid_request",
                    ["error_description"] = "code_challenge required",
                }, state));
            }

            // RFC 7636 §4.3 defaults a missing method to "plain", which this server doesn't support.
            if (usePkce && (code_challenge_method != Pkce.S256 || !Pkce.IsValidChallenge(code_challenge!)))
            {
                return Redirect(OAuthRedirect.Build(redirect_uri, new()
                {
                    ["error"] = "invalid_request",
                    ["error_description"] = "code_challenge_method must be S256 with a valid code_challenge",
                }, state));
            }
        }

        var reqId = InMemoryStore.GenerateToken(8);
        store.PendingAuthorizationRequests[reqId] = new PendingAuthorizationRequest
        {
            ResponseType = response_type,
            ClientId = client_id,
            RedirectUri = redirect_uri,
            Scope = scope ?? "",
            State = state ?? "",
            CodeChallenge = usePkce ? code_challenge : null,
            CodeChallengeMethod = usePkce ? code_challenge_method : null,
        };

        ReqId = reqId;
        ClientName = client.Name;
        RequestedScopes = [.. allowedScopes];
        return Page();
    }
}
