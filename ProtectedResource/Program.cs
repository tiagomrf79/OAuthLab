using System.Net.Http.Headers;
using ProtectedResource;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

// Full JWTs are verified locally, reference tokens are introspected, and minimal JWTs get both —
// see DispatchingAccessTokenValidator.
builder.Services.AddSingleton<JwtAccessTokenValidator>();
builder.Services.AddSingleton<IntrospectionAccessTokenValidator>();
builder.Services.AddSingleton<IAccessTokenValidator, DispatchingAccessTokenValidator>();

// PublicClient calls this endpoint directly from browser JS (unlike ConfidentialClient, which
// calls it server-to-server), so the browser enforces CORS. Vite's dev port can shift, so any
// origin is allowed here rather than pinning one — this is a teaching sandbox, not production.
// WWW-Authenticate is exposed so browser JS can read why a request was refused.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod().WithExposedHeaders("WWW-Authenticate"));
});

var app = builder.Build();

app.UseRouting();
app.UseCors();

// Each operation requires the scope of the same name, so a token granted only "read" can't write.
app.MapGet("/resource/read", (HttpRequest request, IAccessTokenValidator validator) => HandleAsync(request, validator, "read", "Read op executed."));
app.MapPost("/resource/write", (HttpRequest request, IAccessTokenValidator validator) => HandleAsync(request, validator, "write", "Write op executed."));
app.MapDelete("/resource/delete", (HttpRequest request, IAccessTokenValidator validator) => HandleAsync(request, validator, "delete", "Delete op executed."));

app.Run();

static async Task<IResult> HandleAsync(HttpRequest request, IAccessTokenValidator validator, string requiredScope, string message)
{
    var accessToken = await ExtractAccessToken(request);
    if (string.IsNullOrWhiteSpace(accessToken))
    {
        // RFC 6750 §3.1: a request with no token at all gets a bare challenge, no error code.
        request.HttpContext.Response.Headers.WWWAuthenticate = "Bearer";
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
    }

    var token = await validator.ValidateAsync(accessToken);
    if (token is null)
    {
        request.HttpContext.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
    }

    // RFC 6750 §3.1: the token is fine, it just wasn't granted enough — 403, naming the scope needed.
    if (!token.Scopes.Contains(requiredScope))
    {
        request.HttpContext.Response.Headers.WWWAuthenticate = $"Bearer error=\"insufficient_scope\", scope=\"{requiredScope}\"";
        return Results.Json(new { error = "insufficient_scope", scope = requiredScope }, statusCode: 403);
    }

    return Results.Json(new { message });
}

// Per RFC 6750 §2, a bearer token can travel as the Authorization header (preferred),
// a form-encoded body parameter, or a query parameter (discouraged, but supported here
// so all three delivery methods can be exercised).
static async Task<string?> ExtractAccessToken(HttpRequest request)
{
    if (AuthenticationHeaderValue.TryParse(request.Headers.Authorization.ToString(), out var authHeader)
        && string.Equals(authHeader.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(authHeader.Parameter))
    {
        return authHeader.Parameter;
    }

    if (request.HasFormContentType)
    {
        var form = await request.ReadFormAsync();
        if (form.TryGetValue("access_token", out var formToken) && !string.IsNullOrWhiteSpace(formToken))
        {
            return formToken.ToString();
        }
    }

    if (request.Query.TryGetValue("access_token", out var queryToken) && !string.IsNullOrWhiteSpace(queryToken))
    {
        return queryToken.ToString();
    }

    return null;
}
