using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.UseRouting();

app.MapGet("/resource", (HttpRequest request) =>
{
    if (!AuthenticationHeaderValue.TryParse(request.Headers.Authorization.ToString(), out var authHeader)
        || !string.Equals(authHeader.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
        || string.IsNullOrWhiteSpace(authHeader.Parameter))
    {
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);
    }

    return Results.Json(new { message = "Hello! This is a protected resource." });
});

app.Run();
