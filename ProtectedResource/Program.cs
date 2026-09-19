using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// PublicClient calls this endpoint directly from browser JS (unlike ConfidentialClient, which
// calls it server-to-server), so the browser enforces CORS. Vite's dev port can shift, so any
// origin is allowed here rather than pinning one — this is a teaching sandbox, not production.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

var app = builder.Build();

app.UseRouting();
app.UseCors();

app.MapGet("/resource/read", (HttpRequest request) => HandleAsync(request, "Read op executed."));
app.MapPost("/resource/write", (HttpRequest request) => HandleAsync(request, "Write op executed."));
app.MapDelete("/resource/delete", (HttpRequest request) => HandleAsync(request, "Delete op executed."));

app.Run();

// accessToken is only checked for presence — validating it (and the scope it was granted)
// against the authorization server is future work, same as before this endpoint was split
// per scope.
static async Task<IResult> HandleAsync(HttpRequest request, string message)
{
    var accessToken = await ExtractAccessToken(request);
    if (string.IsNullOrWhiteSpace(accessToken))
    {
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
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
