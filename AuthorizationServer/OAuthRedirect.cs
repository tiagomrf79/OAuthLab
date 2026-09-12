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
}
