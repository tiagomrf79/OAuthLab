using System.Security.Claims;
using AuthorizationServer.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthorizationServer.Pages;

public class LoginModel(InMemoryStore store) : PageModel
{
    [BindProperty]
    public string Username { get; set; } = "";

    [BindProperty]
    public string Password { get; set; } = "";

    [BindProperty]
    public string ReturnUrl { get; set; } = "/";

    public string? Error { get; set; }

    public void OnGet(string returnUrl = "/")
    {
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = store.FindUser(Username, Password);
        if (user is null)
        {
            Error = "Invalid username or password.";
            return Page();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Subject),
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Email, user.Email),
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        return LocalRedirect(ReturnUrl);
    }
}
