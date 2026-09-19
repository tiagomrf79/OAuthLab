using Microsoft.AspNetCore.WebUtilities;

namespace AuthorizationServer;

internal static class OAuthRedirect
{
    public static string Build(string redirectUri, Dictionary<string, string?> parameters, string? state)
    {
        if (!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        return QueryHelpers.AddQueryString(redirectUri, parameters);
    }

    // Per RFC 6749 §4.2.2 / §4.2.2.1, the implicit grant returns its token and its errors in the
    // redirect URI fragment rather than the query string — a fragment is never sent to a server
    // (by the browser or in a Referer header), which matters since it's carrying a live token.
    public static string BuildFragment(string redirectUri, Dictionary<string, string?> parameters, string? state)
    {
        if (!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        var fragment = string.Join('&', parameters
            .Where(p => p.Value is not null)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value!)}"));

        return $"{redirectUri}#{fragment}";
    }
}
