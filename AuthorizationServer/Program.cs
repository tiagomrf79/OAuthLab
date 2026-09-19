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
        "client_credentials" => HandleClientCredentialsGrant(form, client, store),
        "password" => HandlePasswordGrant(form, client, store),
        _ => Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400),
    };
});

app.Run();

static bool TryGetClientCredentials(HttpRequest request, IFormCollection form, out string clientId, out string clientSecret)
{
    clientId = "";
    clientSecret = "";

    var hasHeaderCredentials = false;
    var header = request.Headers.Authorization.ToString();
    if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..].Trim()));
            var separatorIndex = decoded.IndexOf(':');
            if (separatorIndex < 0)
            {
                return false;
            }

            clientId = Uri.UnescapeDataString(decoded[..separatorIndex]);
            clientSecret = Uri.UnescapeDataString(decoded[(separatorIndex + 1)..]);
            hasHeaderCredentials = true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    var bodyClientId = form["client_id"].ToString();
    if (!string.IsNullOrEmpty(bodyClientId))
    {
        if (hasHeaderCredentials)
        {
            // The client authenticated with both the Authorization header and body fields at once —
            // reject rather than silently pick one, per RFC 6749 §2.3.1 ("the client MUST NOT use
            // more than one authentication method in each request").
            clientId = "";
            clientSecret = "";
            return false;
        }

        clientId = bodyClientId;
        clientSecret = form["client_secret"].ToString();
    }

    return !string.IsNullOrEmpty(clientId);
}

static IResult HandleAuthorizationCodeGrant(IFormCollection form, Client client, InMemoryStore store)
{
    var code = form["code"].ToString();
    var redirectUri = form["redirect_uri"].ToString();

    // Remove the code on first use, win or lose — a stolen code should be burned, not reusable.
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

static IResult HandleClientCredentialsGrant(IFormCollection form, Client client, InMemoryStore store)
{
    var scope = string.Join(' ', form["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(client.AllowedScopes));

    var accessToken = InMemoryStore.GenerateToken();
    var expiresIn = TimeSpan.FromHours(1);

    store.AccessTokens[accessToken] = new AccessToken
    {
        Token = accessToken,
        ClientId = client.ClientId,
        // No end user in this grant — the client is acting on its own behalf, so it is its own subject.
        Subject = client.ClientId,
        Scope = scope,
        ExpiresAt = DateTimeOffset.UtcNow.Add(expiresIn),
    };

    // No refresh token per RFC 6749 §4.4.3 — the client can just request a new access token with
    // its credentials again, since it authenticates directly on every call.
    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)expiresIn.TotalSeconds,
        scope,
    });
}

static IResult HandlePasswordGrant(IFormCollection form, Client client, InMemoryStore store)
{
    var username = form["username"].ToString();
    var password = form["password"].ToString();

    var user = store.FindUser(username, password);
    if (user is null)
    {
        return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
    }

    var scope = string.Join(' ', form["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(client.AllowedScopes));

    var accessToken = InMemoryStore.GenerateToken();
    var refreshToken = InMemoryStore.GenerateToken();
    var expiresIn = TimeSpan.FromHours(1);

    store.AccessTokens[accessToken] = new AccessToken
    {
        Token = accessToken,
        ClientId = client.ClientId,
        Subject = user.Subject,
        Scope = scope,
        ExpiresAt = DateTimeOffset.UtcNow.Add(expiresIn),
    };
    store.RefreshTokens[refreshToken] = new RefreshToken
    {
        Token = refreshToken,
        ClientId = client.ClientId,
        Subject = user.Subject,
        Scope = scope,
    };

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)expiresIn.TotalSeconds,
        refresh_token = refreshToken,
        scope,
    });
}

static IResult HandleRefreshTokenGrant(IFormCollection form, Client client, InMemoryStore store)
{
    var refreshTokenValue = form["refresh_token"].ToString();

    if (!store.RefreshTokens.TryGetValue(refreshTokenValue, out var refreshToken))
    {
        return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
    }

    if (refreshToken.ClientId != client.ClientId)
    {
        // A refresh token presented by a client other than the one it was issued to has likely
        // been stolen — burn it rather than just refusing this one request.
        store.RefreshTokens.TryRemove(refreshTokenValue, out _);
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
