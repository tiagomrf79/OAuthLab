using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using NativeClient.Models;

namespace NativeClient.Services;

// Shared by every grant-type screen (AuthorizationCodePage today, more to follow) so each one only
// has to describe its own request, not re-implement logging/parsing.
public class OAuthService
{
    private readonly HttpClient _http = new();

    public async Task<(HttpResponseMessage Response, string Body, LogEntry Log)> SendAndLogAsync(string title, HttpRequestMessage request)
    {
        var requestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync();
        var requestUrl = request.RequestUri!.ToString();
        var requestMethod = request.Method.Method;

        var response = await _http.SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();

        var detail =
            $"Request: {requestMethod} {requestUrl}\n{FormatBody(requestBody)}\n\n" +
            $"Response: {(int)response.StatusCode} {response.ReasonPhrase}\n{FormatBody(responseBody)}";

        var log = new LogEntry { Time = DateTimeOffset.Now.ToString("T"), Title = title, Detail = detail };
        return (response, responseBody, log);
    }

    public static TokenResponse? DeserializeToken(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<TokenResponse>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static ClientRegistrationResponse? DeserializeRegistration(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<ClientRegistrationResponse>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static AuthenticationHeaderValue BasicAuthHeader(string clientId, string clientSecret)
    {
        var credentials = $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}";
        return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
    }

    private static string FormatBody(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return "(empty body)";
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            return JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException)
        {
            return text;
        }
    }
}
