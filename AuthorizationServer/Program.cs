using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthorizationServer;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddSingleton<InMemoryStore>();
builder.Services.AddSingleton<AccessTokenIssuer>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.Cookie.Name = "AuthorizationServer.Auth";
    });

// PublicClient calls /token (authorization code + PKCE page) and /revoke (both pages) directly from
// browser JS, so the browser enforces CORS there. Applied to those two only — /authorize and
// /approve are full-page navigations, not fetches. Any origin is allowed since Vite's dev port can shift (same trade-off
// as ProtectedResource) — this is a teaching sandbox, not production.
const string TokenCorsPolicy = "TokenEndpoint";
builder.Services.AddCors(options =>
{
    options.AddPolicy(TokenCorsPolicy, policy => policy.AllowAnyOrigin().AllowAnyHeader().WithMethods("POST"));
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
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.MapPost("/token", async (HttpRequest request, InMemoryStore store, AccessTokenIssuer tokens) =>
{
    if (!request.HasFormContentType)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: 400);
    }

    var form = await request.ReadFormAsync();

    if (!TryAuthenticateClient(request, form, store, out var client) || client is null)
    {
        return Results.Json(new { error = "invalid_client" }, statusCode: 401);
    }

    var grantType = form["grant_type"].ToString();
    if (!client.GrantTypes.Contains(grantType))
    {
        // RFC 6749 §5.2 — the grant type is a real one, just not one this client registered for.
        return Results.Json(new { error = "unauthorized_client" }, statusCode: 400);
    }

    return grantType switch
    {
        "authorization_code" => HandleAuthorizationCodeGrant(form, client, store, tokens),
        "refresh_token" => HandleRefreshTokenGrant(form, client, store, tokens),
        "client_credentials" => HandleClientCredentialsGrant(form, client, tokens),
        "password" => HandlePasswordGrant(form, client, store, tokens),
        _ => Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400),
    };
}).RequireCors(TokenCorsPolicy);

// Public half of the access token signing key (RFC 7517), so a protected resource can verify the
// JWTs AccessTokenIssuer mints without sharing any secret with this server.
app.MapGet("/.well-known/jwks.json", (AccessTokenIssuer tokens) => Results.Json(tokens.GetJsonWebKeySet()));

// RFC 7662 token introspection — the alternative to verifying the JWT locally: a protected resource
// hands the token back here and asks whether it's still active. Slower (a network hop per check)
// but authoritative, since it reflects this server's current record rather than what the token
// said when it was minted — a token this server has forgotten (or, later, revoked) is inactive
// here even while its signature and exp still look fine.
app.MapPost("/introspect", async (HttpRequest request, InMemoryStore store, AccessTokenIssuer tokens) =>
{
    // §2.1: the caller must be authorized, otherwise anyone could use this endpoint to find out
    // whether a token they found is live. Only registered resource servers get in, not clients.
    if (!TryParseBasicCredentials(request.Headers.Authorization.ToString(), out var resourceId, out var resourceSecret)
        || store.FindResourceServer(resourceId) is not { } resource
        || resource.ResourceSecret != resourceSecret)
    {
        request.HttpContext.Response.Headers.WWWAuthenticate = "Basic";
        return Results.Json(new { error = "invalid_client" }, statusCode: 401);
    }

    if (!request.HasFormContentType)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: 400);
    }

    var form = await request.ReadFormAsync();

    // Only access tokens are introspectable — a resource server has no business learning anything
    // about refresh tokens, which only the client and this server should ever see. token_type_hint
    // is optional (§2.1) and ignored, since there's only one kind of token to look in.
    if (!store.AccessTokens.TryGetValue(form["token"].ToString(), out var accessToken)
        || accessToken.ExpiresAt < DateTimeOffset.UtcNow)
    {
        // §2.2: an inactive token gets exactly this and nothing else — no hint as to *why* it's
        // inactive (unknown vs. expired vs. revoked), which would only help someone probing tokens.
        return Results.Json(new { active = false });
    }

    return Results.Json(new
    {
        active = true,
        scope = accessToken.Scope,
        client_id = accessToken.ClientId,
        sub = accessToken.Subject,
        token_type = "Bearer",
        exp = accessToken.ExpiresAt.ToUnixTimeSeconds(),
        iss = tokens.Issuer,
        aud = tokens.Audience,
    });
});

// RFC 7009 token revocation — a client telling this server it's done with a token (logout,
// uninstall, "disconnect this app"). Removing the record makes reference and minimal-JWT tokens
// inactive at /introspect straight away; a full JWT is still accepted by ProtectedResource until it
// expires, since nothing there asks this server about it — that gap is left visible on purpose.
app.MapPost("/revoke", async (HttpRequest request, InMemoryStore store) =>
{
    if (!request.HasFormContentType)
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: 400);
    }

    var form = await request.ReadFormAsync();

    // §2.1: the same client authentication as /token — including "none" clients, which identify
    // themselves by client_id alone.
    if (!TryAuthenticateClient(request, form, store, out var client) || client is null)
    {
        return Results.Json(new { error = "invalid_client" }, statusCode: 401);
    }

    var token = form["token"].ToString();
    if (string.IsNullOrEmpty(token))
    {
        return Results.Json(new { error = "invalid_request" }, statusCode: 400);
    }

    // token_type_hint is only an optimization (§2.1): the server must look in every token store
    // anyway if the hint doesn't find it, and with two in-memory lookups there's nothing to save.
    if (store.RefreshTokens.TryGetValue(token, out var refreshToken))
    {
        // A refresh token takes its whole grant with it — every access token minted from it too.
        if (refreshToken.ClientId == client.ClientId)
        {
            store.RevokeGrant(refreshToken.GrantId);
        }
    }
    else if (store.AccessTokens.TryGetValue(token, out var accessToken))
    {
        // An access token goes alone. §2.1 allows also revoking its refresh token, but that would
        // punish a client for tidying up one token it no longer needs.
        if (accessToken.ClientId == client.ClientId)
        {
            store.AccessTokens.TryRemove(token, out _);
        }
    }

    // §2.2: 200 whether or not anything was removed — the token is unusable either way, which is
    // all the client asked for. That includes a token belonging to a *different* client: §2.1 says
    // to refuse that with an error, but an error would confirm to the caller that the token exists
    // and whose it is, so it's silently ignored instead.
    return Results.Ok();
}).RequireCors(TokenCorsPolicy);

// RFC 7591 dynamic client registration — lets a native client obtain its own client_id/secret at
// runtime instead of shipping a static one baked into every install (see NativeClient's
// AuthorizationCodePage, which calls this the first time it needs a token and has none yet).
app.MapPost("/register", async (HttpRequest request, InMemoryStore store) =>
{
    if (!request.HasJsonContentType())
    {
        return Results.Json(new { error = "invalid_client_metadata" }, statusCode: 400);
    }

    var (error, metadata) = ValidateClientMetadata(await request.ReadFromJsonAsync<ClientRegistrationRequest>());
    if (error is not null || metadata is null)
    {
        return Results.Json(new { error }, statusCode: 400);
    }

    var client = new Client
    {
        ClientId = InMemoryStore.GenerateToken(16),
        // A "none" client authenticates with no secret at all, so there's nothing to protect by
        // minting one — it would just be a value the client never sends and never needs.
        ClientSecret = metadata.TokenEndpointAuthMethod == "none" ? "" : InMemoryStore.GenerateToken(32),
        // Separate from ClientSecret — this is what authorizes the RFC 7592 management calls below,
        // not requests to /token.
        RegistrationAccessToken = InMemoryStore.GenerateToken(24),
        ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        Name = metadata.Name,
        RedirectUris = metadata.RedirectUris,
        AllowedScopes = metadata.AllowedScopes,
        TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod,
        GrantTypes = metadata.GrantTypes,
        ResponseTypes = metadata.ResponseTypes,
        RequirePkce = metadata.RequirePkce,
        AccessTokenFormat = metadata.AccessTokenFormat,
    };
    store.Clients[client.ClientId] = client;

    return RegistrationResponse(client, request, statusCode: 201);
});

// RFC 7592 client configuration management — lets a client read, replace, or delete its own
// registration using the registration_access_token it got back from POST /register. This is
// deliberately separate from admin/general client lookup: the bearer token below is the only
// thing that authorizes these calls, and it's scoped to exactly one client_id.
app.MapGet("/register/{clientId}", (string clientId, HttpRequest request, InMemoryStore store) =>
{
    if (!TryAuthorizeClientManagement(request, store, clientId, out var client) || client is null)
    {
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
    }

    return RegistrationResponse(client, request);
});

app.MapPut("/register/{clientId}", async (string clientId, HttpRequest request, InMemoryStore store) =>
{
    if (!TryAuthorizeClientManagement(request, store, clientId, out var existing) || existing is null)
    {
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
    }

    if (!request.HasJsonContentType())
    {
        return Results.Json(new { error = "invalid_client_metadata" }, statusCode: 400);
    }

    var (error, metadata) = ValidateClientMetadata(await request.ReadFromJsonAsync<ClientRegistrationRequest>());
    if (error is not null || metadata is null)
    {
        return Results.Json(new { error }, statusCode: 400);
    }

    // PUT is a full replace per RFC 7592 §2.2, not a merge — fields left out of the body (e.g. no
    // grant_types) fall back to ValidateClientMetadata's defaults rather than keeping the old ones.
    var authMethodChangedToNone = metadata.TokenEndpointAuthMethod == "none" && existing.TokenEndpointAuthMethod != "none";
    var authMethodChangedFromNone = metadata.TokenEndpointAuthMethod != "none" && existing.TokenEndpointAuthMethod == "none";

    var updated = new Client
    {
        ClientId = existing.ClientId,
        ClientSecret = authMethodChangedToNone ? "" : authMethodChangedFromNone ? InMemoryStore.GenerateToken(32) : existing.ClientSecret,
        RegistrationAccessToken = existing.RegistrationAccessToken,
        ClientIdIssuedAt = existing.ClientIdIssuedAt,
        Name = metadata.Name,
        RedirectUris = metadata.RedirectUris,
        AllowedScopes = metadata.AllowedScopes,
        TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod,
        GrantTypes = metadata.GrantTypes,
        ResponseTypes = metadata.ResponseTypes,
        RequirePkce = metadata.RequirePkce,
        AccessTokenFormat = metadata.AccessTokenFormat,
    };
    store.Clients[clientId] = updated;

    return RegistrationResponse(updated, request);
});

app.MapDelete("/register/{clientId}", (string clientId, HttpRequest request, InMemoryStore store) =>
{
    if (!TryAuthorizeClientManagement(request, store, clientId, out _))
    {
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
    }

    store.Clients.TryRemove(clientId, out _);
    return Results.NoContent();
});

app.Run();

// Identifies which client is calling and how (Basic header vs. POST body vs. no secret at all),
// then checks both that the secret is correct AND that the method used matches what the client
// registered with — a client can't just switch to whichever method happens to work.
static bool TryAuthenticateClient(HttpRequest request, IFormCollection form, InMemoryStore store, out Client? client)
{
    client = null;

    var hasHeaderCredentials = false;
    var headerClientId = "";
    var headerClientSecret = "";
    var header = request.Headers.Authorization.ToString();
    if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        if (!TryParseBasicCredentials(header, out headerClientId, out headerClientSecret))
        {
            return false;
        }

        hasHeaderCredentials = true;
    }

    var bodyClientId = form["client_id"].ToString();
    if (hasHeaderCredentials && !string.IsNullOrEmpty(bodyClientId))
    {
        // The client authenticated with both the Authorization header and body fields at once —
        // reject rather than silently pick one, per RFC 6749 §2.3.1 ("the client MUST NOT use
        // more than one authentication method in each request").
        return false;
    }

    string clientId;
    string? providedSecret;
    string usedMethod;

    if (hasHeaderCredentials)
    {
        clientId = headerClientId;
        providedSecret = headerClientSecret;
        usedMethod = "client_secret_basic";
    }
    else if (!string.IsNullOrEmpty(bodyClientId))
    {
        clientId = bodyClientId;
        var bodyClientSecret = form["client_secret"].ToString();
        if (!string.IsNullOrEmpty(bodyClientSecret))
        {
            providedSecret = bodyClientSecret;
            usedMethod = "client_secret_post";
        }
        else
        {
            providedSecret = null;
            usedMethod = "none";
        }
    }
    else
    {
        return false;
    }

    var foundClient = store.FindClient(clientId);
    if (foundClient is null || foundClient.TokenEndpointAuthMethod != usedMethod)
    {
        return false;
    }

    if (usedMethod != "none" && foundClient.ClientSecret != providedSecret)
    {
        return false;
    }

    client = foundClient;
    return true;
}

// RFC 6749 §2.3.1: id and secret are form-urlencoded before being joined with ':' and base64'd.
static bool TryParseBasicCredentials(string header, out string id, out string secret)
{
    id = "";
    secret = "";

    if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    try
    {
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..].Trim()));
        var separatorIndex = decoded.IndexOf(':');
        if (separatorIndex < 0)
        {
            return false;
        }

        id = Uri.UnescapeDataString(decoded[..separatorIndex]);
        secret = Uri.UnescapeDataString(decoded[(separatorIndex + 1)..]);
        return true;
    }
    catch (FormatException)
    {
        return false;
    }
}

// A registration access token, presented as "Authorization: Bearer <token>", is a separate secret
// from the client's OAuth client_secret — it only ever authorizes calls to this client's own
// /register/{client_id} endpoint. A client with no RegistrationAccessToken (the statically-seeded
// ones) can never present a matching token, so this always fails closed for them.
static bool TryAuthorizeClientManagement(HttpRequest request, InMemoryStore store, string clientId, out Client? client)
{
    client = null;

    var header = request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    var token = header["Bearer ".Length..].Trim();
    if (string.IsNullOrEmpty(token))
    {
        return false;
    }

    var found = store.FindClient(clientId);
    if (found?.RegistrationAccessToken is null || found.RegistrationAccessToken != token)
    {
        return false;
    }

    client = found;
    return true;
}

// Shared by POST /register and PUT /register/{client_id} — validates and defaults/cross-derives
// client metadata the same way both times, so a client's registration can't drift depending on
// which of those two calls produced it.
static (string? Error, ClientMetadata? Metadata) ValidateClientMetadata(ClientRegistrationRequest? body)
{
    if (body is null)
    {
        return ("invalid_client_metadata", null);
    }

    var authMethod = string.IsNullOrEmpty(body.TokenEndpointAuthMethod) ? "client_secret_basic" : body.TokenEndpointAuthMethod;
    if (!InMemoryStore.KnownAuthMethods.Contains(authMethod))
    {
        return ("invalid_client_metadata", null);
    }

    // Mirrors the reference "OAuth 2 in Action" registration endpoint: default and cross-derive
    // grant_types/response_types from whichever one was actually supplied, so a caller that only
    // says "I want response_type=code" doesn't also have to spell out grant_type=authorization_code.
    string[] grantTypes;
    string[] responseTypes;
    if (body.GrantTypes is not { Length: > 0 })
    {
        if (body.ResponseTypes is not { Length: > 0 })
        {
            grantTypes = ["authorization_code"];
            responseTypes = ["code"];
        }
        else
        {
            responseTypes = body.ResponseTypes;
            grantTypes = responseTypes.Contains("code") ? ["authorization_code"] : [];
        }
    }
    else if (body.ResponseTypes is not { Length: > 0 })
    {
        grantTypes = body.GrantTypes;
        responseTypes = grantTypes.Contains("authorization_code") ? ["code"] : [];
    }
    else
    {
        grantTypes = body.GrantTypes;
        responseTypes = body.ResponseTypes;
        if (grantTypes.Contains("authorization_code") && !responseTypes.Contains("code"))
        {
            responseTypes = [.. responseTypes, "code"];
        }
        if (!grantTypes.Contains("authorization_code") && responseTypes.Contains("code"))
        {
            grantTypes = [.. grantTypes, "authorization_code"];
        }
    }

    // Dynamic registration is restricted to authorization_code (+ refresh_token) / code — the
    // client_credentials, password and implicit grants stay reserved for the statically-seeded
    // clients that this lab already trusts by configuration.
    if (grantTypes.Except(InMemoryStore.RegistrableGrantTypes).Any() || responseTypes.Except(InMemoryStore.RegistrableResponseTypes).Any())
    {
        return ("invalid_client_metadata", null);
    }

    // Only redirect-based flows (anything with a response_type) need somewhere to send the browser
    // back to; a client registering without one (e.g. refresh_token only) doesn't have to supply one.
    var redirectUris = body.RedirectUris ?? [];
    if (responseTypes.Length > 0 && redirectUris.Length == 0)
    {
        return ("invalid_redirect_uri", null);
    }

    if (!redirectUris.All(IsAcceptableRedirectUri))
    {
        return ("invalid_redirect_uri", null);
    }

    var scope = string.Join(' ', (body.Scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(InMemoryStore.KnownScopes));

    // A "none" client has no secret, so PKCE is the only thing binding its code to the app that
    // requested it — it can't opt out. Confidential clients default to optional PKCE.
    if (authMethod == "none" && body.RequirePkce == false)
    {
        return ("invalid_client_metadata", null);
    }
    var requirePkce = body.RequirePkce ?? authMethod == "none";

    var accessTokenFormat = string.IsNullOrEmpty(body.AccessTokenFormat) ? "jwt" : body.AccessTokenFormat;
    if (!InMemoryStore.KnownAccessTokenFormats.Contains(accessTokenFormat))
    {
        return ("invalid_client_metadata", null);
    }

    var metadata = new ClientMetadata(
        Name: string.IsNullOrWhiteSpace(body.ClientName) ? "Dynamically Registered Client" : body.ClientName,
        RedirectUris: redirectUris,
        AllowedScopes: scope.Split(' ', StringSplitOptions.RemoveEmptyEntries),
        TokenEndpointAuthMethod: authMethod,
        GrantTypes: grantTypes,
        ResponseTypes: responseTypes,
        RequirePkce: requirePkce,
        AccessTokenFormat: accessTokenFormat);

    return (null, metadata);
}

// RFC 6749 §3.1.2: a redirect URI MUST be absolute and MUST NOT carry a fragment. On top of that,
// RFC 7591 §5 / RFC 8252 guidance on which schemes make sense for which clients:
//   https              — any host.
//   http               — loopback only (a native app's local listener, or local development);
//                        anywhere else the code would cross the network in the clear.
//   custom (myapp://)  — native apps' private-use schemes, e.g. NativeClient's nativeclient://.
//   javascript:, data:, vbscript:, file: — never: they'd run or read something instead of navigating.
static bool IsAcceptableRedirectUri(string value)
{
    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment) || value.Contains('#'))
    {
        return false;
    }

    return uri.Scheme switch
    {
        "https" => true,
        "http" => uri.IsLoopback,
        "javascript" or "data" or "vbscript" or "file" => false,
        _ => true,
    };
}

// Registration responses carry secrets (client_secret, registration_access_token), so they must not
// be cached — the same rule RFC 6749 §5.1 sets for /token, and what RFC 7591 §3.2.1's examples send.
// Absent values (no client_secret for a "none" client) are left out rather than sent as null.
static IResult RegistrationResponse(Client client, HttpRequest request, int statusCode = 200)
{
    request.HttpContext.Response.Headers.CacheControl = "no-store";
    request.HttpContext.Response.Headers.Pragma = "no-cache";
    return Results.Json(BuildRegistrationResponse(client, request), RegistrationJson.Options, statusCode: statusCode);
}

static object BuildRegistrationResponse(Client client, HttpRequest request) => new
{
    client_id = client.ClientId,
    client_secret = client.TokenEndpointAuthMethod == "none" ? null : client.ClientSecret,
    client_id_issued_at = client.ClientIdIssuedAt,
    client_secret_expires_at = 0,
    client_name = client.Name,
    redirect_uris = client.RedirectUris,
    token_endpoint_auth_method = client.TokenEndpointAuthMethod,
    grant_types = client.GrantTypes,
    response_types = client.ResponseTypes,
    scope = string.Join(' ', client.AllowedScopes),
    require_pkce = client.RequirePkce,
    access_token_format = client.AccessTokenFormat,
    registration_access_token = client.RegistrationAccessToken,
    registration_client_uri = client.RegistrationAccessToken is null
        ? null
        : $"{request.Scheme}://{request.Host}/register/{client.ClientId}",
};

static IResult HandleAuthorizationCodeGrant(IFormCollection form, Client client, InMemoryStore store, AccessTokenIssuer tokens)
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

    // PKCE (RFC 7636) is decided per code, not per client: a code issued with a challenge needs the
    // matching verifier, and a code issued without one must not be redeemed with a verifier — that
    // mismatch means the client started a PKCE request but got someone else's code back (the
    // injection/downgrade case in RFC 9700 §2.1.1). The code is already burned above either way.
    var codeVerifier = form["code_verifier"].ToString();
    if (authCode.CodeChallenge is null)
    {
        // RequirePkce is enforced at /authorize; this only catches a client whose registration was
        // switched to require PKCE (PUT /register/{id}) after this code was issued.
        if (!string.IsNullOrEmpty(codeVerifier) || client.RequirePkce)
        {
            return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        }
    }
    else if (string.IsNullOrEmpty(codeVerifier) || !Pkce.VerifierMatches(codeVerifier, authCode.CodeChallenge))
    {
        return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
    }

    // Redeeming the code starts a new grant; the refresh token carries its id so every access token
    // minted from it later belongs to the same grant.
    var grantId = InMemoryStore.GenerateGrantId();
    var accessToken = tokens.Issue(client, authCode.Subject, authCode.Scope, grantId);
    // The refresh token stays opaque — only this server ever reads it, so there's nothing to gain
    // from making it self-contained, and a store lookup is what lets it be burned on misuse.
    var refreshToken = InMemoryStore.GenerateToken();

    store.RefreshTokens[refreshToken] = new RefreshToken
    {
        Token = refreshToken,
        ClientId = client.ClientId,
        Subject = authCode.Subject,
        Scope = authCode.Scope,
        GrantId = grantId,
    };

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)AccessTokenIssuer.Lifetime.TotalSeconds,
        refresh_token = refreshToken,
        scope = authCode.Scope,
    });
}

static IResult HandleClientCredentialsGrant(IFormCollection form, Client client, AccessTokenIssuer tokens)
{
    var scope = string.Join(' ', form["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(client.AllowedScopes));

    // No end user in this grant — the client is acting on its own behalf, so it is its own subject.
    var accessToken = tokens.Issue(client, client.ClientId, scope, InMemoryStore.GenerateGrantId());

    // No refresh token per RFC 6749 §4.4.3 — the client can just request a new access token with
    // its credentials again, since it authenticates directly on every call.
    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)AccessTokenIssuer.Lifetime.TotalSeconds,
        scope,
    });
}

static IResult HandlePasswordGrant(IFormCollection form, Client client, InMemoryStore store, AccessTokenIssuer tokens)
{
    var username = form["username"].ToString();
    var password = form["password"].ToString();

    var user = store.FindUser(username, password);
    if (user is null)
    {
        return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
    }

    var scope = string.Join(' ', form["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Intersect(client.AllowedScopes));

    var grantId = InMemoryStore.GenerateGrantId();
    var accessToken = tokens.Issue(client, user.Subject, scope, grantId);
    var refreshToken = InMemoryStore.GenerateToken();

    store.RefreshTokens[refreshToken] = new RefreshToken
    {
        Token = refreshToken,
        ClientId = client.ClientId,
        Subject = user.Subject,
        Scope = scope,
        GrantId = grantId,
    };

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)AccessTokenIssuer.Lifetime.TotalSeconds,
        refresh_token = refreshToken,
        scope,
    });
}

static IResult HandleRefreshTokenGrant(IFormCollection form, Client client, InMemoryStore store, AccessTokenIssuer tokens)
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

    // Same grant as the refresh token, so revoking the refresh token takes this access token with it.
    var accessToken = tokens.Issue(client, refreshToken.Subject, refreshToken.Scope, refreshToken.GrantId);

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)AccessTokenIssuer.Lifetime.TotalSeconds,
        refresh_token = refreshTokenValue,
        scope = refreshToken.Scope,
    });
}

// The subset of Client fields a registration request actually supplies — deliberately missing
// ClientId/ClientSecret/RegistrationAccessToken/ClientIdIssuedAt, which only POST /register and
// PUT /register/{client_id} know how to assign (a fresh id and secret, or an existing one to keep).
internal record ClientMetadata(
    string Name,
    string[] RedirectUris,
    string[] AllowedScopes,
    string TokenEndpointAuthMethod,
    string[] GrantTypes,
    string[] ResponseTypes,
    bool RequirePkce,
    string AccessTokenFormat);

internal static class RegistrationJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
