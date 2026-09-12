using System.Text;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddSingleton<InMemoryStore>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.Cookie.Name = "AuthorizationServer.Auth";
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.MapPost("/token", async (HttpRequest request, InMemoryStore store) =>
{
    if (!request.HasFormContentType)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: 400);
    }

    var form = await request.ReadFormAsync();

    if (!TryGetClientCredentials(request, form, out var clientId, out var clientSecret))
    {
        return Results.Json(new { error = "invalid_client" }, statusCode: 401);
    }

    var client = store.FindClient(clientId);
    if (client is null || client.ClientSecret != clientSecret)
    {
        return Results.Json(new { error = "invalid_client" }, statusCode: 401);
    }

    return form["grant_type"].ToString() switch
    {
        "authorization_code" => HandleAuthorizationCodeGrant(form, client, store),
        "refresh_token" => HandleRefreshTokenGrant(form, client, store),
        _ => Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400),
    };
});

app.Run();

static bool TryGetClientCredentials(HttpRequest request, IFormCollection form, out string clientId, out string clientSecret)
{
    var header = request.Headers.Authorization.ToString();
    if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..].Trim()));
            var separatorIndex = decoded.IndexOf(':');
            if (separatorIndex < 0)
            {
                clientId = "";
                clientSecret = "";
                return false;
            }

            clientId = Uri.UnescapeDataString(decoded[..separatorIndex]);
            clientSecret = Uri.UnescapeDataString(decoded[(separatorIndex + 1)..]);
            return true;
        }
        catch (FormatException)
        {
            clientId = "";
            clientSecret = "";
            return false;
        }
    }

    clientId = form["client_id"].ToString();
    clientSecret = form["client_secret"].ToString();
    return !string.IsNullOrEmpty(clientId);
}

static IResult HandleAuthorizationCodeGrant(IFormCollection form, Client client, InMemoryStore store)
{
    var code = form["code"].ToString();
    var redirectUri = form["redirect_uri"].ToString();

    if (!store.AuthorizationCodes.TryRemove(code, out var authCode)
        || authCode.ClientId != client.ClientId
        || authCode.RedirectUri != redirectUri
        || authCode.ExpiresAt < DateTimeOffset.UtcNow)
    {
        return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
    }

    var accessToken = InMemoryStore.GenerateToken();
    var refreshToken = InMemoryStore.GenerateToken();
    var expiresIn = TimeSpan.FromHours(1);

    store.AccessTokens[accessToken] = new AccessToken
    {
        Token = accessToken,
        ClientId = client.ClientId,
        Subject = authCode.Subject,
        Scope = authCode.Scope,
        ExpiresAt = DateTimeOffset.UtcNow.Add(expiresIn),
    };
    store.RefreshTokens[refreshToken] = new RefreshToken
    {
        Token = refreshToken,
        ClientId = client.ClientId,
        Subject = authCode.Subject,
        Scope = authCode.Scope,
    };

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)expiresIn.TotalSeconds,
        refresh_token = refreshToken,
        scope = authCode.Scope,
    });
}

static IResult HandleRefreshTokenGrant(IFormCollection form, Client client, InMemoryStore store)
{
    var refreshTokenValue = form["refresh_token"].ToString();

    if (!store.RefreshTokens.TryGetValue(refreshTokenValue, out var refreshToken) || refreshToken.ClientId != client.ClientId)
    {
        return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
    }

    var accessToken = InMemoryStore.GenerateToken();
    var expiresIn = TimeSpan.FromHours(1);

    store.AccessTokens[accessToken] = new AccessToken
    {
        Token = accessToken,
        ClientId = client.ClientId,
        Subject = refreshToken.Subject,
        Scope = refreshToken.Scope,
        ExpiresAt = DateTimeOffset.UtcNow.Add(expiresIn),
    };

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)expiresIn.TotalSeconds,
        refresh_token = refreshTokenValue,
        scope = refreshToken.Scope,
    });
}
