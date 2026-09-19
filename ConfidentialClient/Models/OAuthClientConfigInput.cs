namespace ConfidentialClient.Models;

// Bound straight from the Configuration form fields on every action button — there is no
// separate "Save" step; whichever fields are showing when a button is clicked are the ones used.
public class OAuthClientConfigInput
{
    public string? AuthorizeEndpoint { get; set; }
    public string? TokenEndpoint { get; set; }
    public string? ResourceEndpoint { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? RedirectUri { get; set; }
    public string? Scope { get; set; }

    // Which page an action shared between flow pages (fetch resource, reset, clear log) should
    // redirect back to — set from a hidden field on each flow's form.
    public string? ReturnTo { get; set; }
}
