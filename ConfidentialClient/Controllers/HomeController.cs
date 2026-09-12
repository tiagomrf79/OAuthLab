using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using ConfidentialClient.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace ConfidentialClient.Controllers;

// A confidential (server-side) OAuth client. Each step of the flow is its own action —
// Authorize, Callback, ExchangeToken, RefreshToken, FetchResource — and every HTTP call the
// server makes on the flow's behalf is logged in full as a request/response console.
public class HomeController(IHttpClientFactory httpClientFactory, IConfiguration config) : Controller
{
    private const string StateKey = "oauth.state";
    private const string CodeKey = "oauth.code";
    private const string AccessTokenKey = "oauth.access_token";
    private const string TokenTypeKey = "oauth.token_type";
    private const string ExpiresInKey = "oauth.expires_in";
    private const string RefreshTokenKey = "oauth.refresh_token";
    private const string ScopeKey = "oauth.scope";
    private const string LogKey = "oauth.log";

    private const string CfgAuthorizeEndpointKey = "cfg.authorize_endpoint";
    private const string CfgTokenEndpointKey = "cfg.token_endpoint";
    private const string CfgResourceEndpointKey = "cfg.resource_endpoint";
    private const string CfgClientIdKey = "cfg.client_id";
    private const string CfgClientSecretKey = "cfg.client_secret";
    private const string CfgRedirectUriKey = "cfg.redirect_uri";
    private const string CfgScopeKey = "cfg.scope";

    [HttpGet("/")]
    public IActionResult Index()
    {
        return View(BuildViewModel());
    }

    [HttpPost("/authorize")]
    public IActionResult Authorize(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);
        ClearTokens();

        var state = RandomToken();
        HttpContext.Session.SetString(StateKey, state);

        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = cfg.ClientId,
            ["redirect_uri"] = cfg.RedirectUri,
            ["scope"] = cfg.Scope,
            ["state"] = state,
        };
        var url = QueryHelpers.AddQueryString(cfg.AuthorizeEndpoint, query);

        AppendLog(new LogEntry
        {
            Title = "Redirect to authorization server",
            Request = new LogBlock { Method = "GET", Url = url },
        });

        return Redirect(url);
    }

    [HttpGet("/callback")]
    public IActionResult Callback(string? code, string? state, string? error, string? error_description)
    {
        if (error is not null)
        {
            AppendLog(new LogEntry
            {
                Title = "Redirect from authorization server — error",
                Response = new LogBlock
                {
                    Method = "GET",
                    Url = Request.GetEncodedUrl(),
                    Body = $"error: {error}\ndescription: {error_description ?? "(none)"}",
                },
            });
            return RedirectToAction(nameof(Index));
        }

        var expectedState = HttpContext.Session.GetString(StateKey);
        if (state != expectedState)
        {
            AppendLog(new LogEntry
            {
                Title = "Redirect from authorization server — state mismatch",
                Response = new LogBlock
                {
                    Method = "GET",
                    Url = Request.GetEncodedUrl(),
                    Body = $"expected state: {expectedState}\nreceived state: {state}",
                },
            });
            return RedirectToAction(nameof(Index));
        }

        HttpContext.Session.SetString(CodeKey, code ?? "");
        AppendLog(new LogEntry
        {
            Title = "Redirect from authorization server",
            Response = new LogBlock
            {
                Method = "GET",
                Url = Request.GetEncodedUrl(),
                Headers = new Dictionary<string, string> { ["Referer"] = Request.Headers.Referer.ToString() },
            },
        });

        return RedirectToAction(nameof(Index));
    }

    [HttpPost("/exchange_token")]
    public async Task<IActionResult> ExchangeToken(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        var code = HttpContext.Session.GetString(CodeKey);
        if (string.IsNullOrEmpty(code))
        {
            TempData["Error"] = "No authorization code in session — run \"Start Authorization Request\" first.";
            return RedirectToAction(nameof(Index));
        }

        var request = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = cfg.RedirectUri,
            }),
        };
        request.Headers.Authorization = BasicAuthHeader(cfg);

        var (response, body) = await SendAndLogAsync("Exchange code for tokens", request);
        if (response.IsSuccessStatusCode)
        {
            StoreTokens(Deserialize(body));
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost("/refresh_token")]
    public async Task<IActionResult> RefreshToken(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        var refreshToken = HttpContext.Session.GetString(RefreshTokenKey);
        if (string.IsNullOrEmpty(refreshToken))
        {
            TempData["Error"] = "No refresh token in session.";
            return RedirectToAction(nameof(Index));
        }

        var request = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
            }),
        };
        request.Headers.Authorization = BasicAuthHeader(cfg);

        var (response, body) = await SendAndLogAsync("Refresh access token", request);
        if (response.IsSuccessStatusCode)
        {
            StoreTokens(Deserialize(body));
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost("/fetch_resource")]
    public async Task<IActionResult> FetchResource(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        var accessToken = HttpContext.Session.GetString(AccessTokenKey);
        if (string.IsNullOrEmpty(accessToken))
        {
            TempData["Error"] = "No access token in session.";
            return RedirectToAction(nameof(Index));
        }

        var request = new HttpRequestMessage(HttpMethod.Get, cfg.ResourceEndpoint)
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) },
        };

        await SendAndLogAsync("Call protected resource", request);
        return RedirectToAction(nameof(Index));
    }

    [HttpGet("/reset")]
    public IActionResult Reset()
    {
        ClearTokens();
        return RedirectToAction(nameof(Index));
    }

    [HttpGet("/clear_log")]
    public IActionResult ClearLog()
    {
        HttpContext.Session.Remove(LogKey);
        return RedirectToAction(nameof(Index));
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    private async Task<(HttpResponseMessage Response, string Body)> SendAndLogAsync(string title, HttpRequestMessage request)
    {
        var requestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync();
        var requestHeaders = MergeHeaders(request.Headers, request.Content?.Headers);
        var requestUrl = request.RequestUri!.ToString();
        var requestMethod = request.Method.Method;

        var response = await httpClientFactory.CreateClient().SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();

        AppendLog(new LogEntry
        {
            Title = title,
            Request = new LogBlock
            {
                Method = requestMethod,
                Url = requestUrl,
                Headers = requestHeaders,
                Body = FormatJson(requestBody),
            },
            Response = new LogBlock
            {
                Status = (int)response.StatusCode,
                StatusText = response.ReasonPhrase,
                Headers = MergeHeaders(response.Headers, response.Content.Headers),
                Body = FormatJson(responseBody),
            },
        });

        return (response, responseBody);
    }

    private void ClearTokens()
    {
        foreach (var key in new[] { StateKey, CodeKey, AccessTokenKey, TokenTypeKey, ExpiresInKey, RefreshTokenKey, ScopeKey })
        {
            HttpContext.Session.Remove(key);
        }
    }

    private static AuthenticationHeaderValue BasicAuthHeader(OAuthClientConfig cfg)
    {
        var credentials = $"{Uri.EscapeDataString(cfg.ClientId)}:{Uri.EscapeDataString(cfg.ClientSecret)}";
        return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(credentials)));
    }

    // Used only to pre-fill the Configuration form on a fresh GET / — once any action button has
    // been clicked, the values it submitted (via BuildConfig/SaveConfig) take over from there.
    private OAuthClientConfig GetEffectiveConfig() => new()
    {
        AuthorizeEndpoint = GetSetting(CfgAuthorizeEndpointKey, "AuthorizationServer:AuthorizeEndpoint"),
        TokenEndpoint = GetSetting(CfgTokenEndpointKey, "AuthorizationServer:TokenEndpoint"),
        ResourceEndpoint = GetSetting(CfgResourceEndpointKey, "ProtectedResource:ResourceEndpoint"),
        ClientId = GetSetting(CfgClientIdKey, "Client:ClientId"),
        ClientSecret = GetSetting(CfgClientSecretKey, "Client:ClientSecret"),
        RedirectUri = GetSetting(CfgRedirectUriKey, "Client:RedirectUri"),
        Scope = GetSetting(CfgScopeKey, "Client:Scope"),
    };

    private string GetSetting(string sessionKey, string configKey) =>
        HttpContext.Session.GetString(sessionKey) ?? config[configKey] ?? "";

    // Model binding converts an empty submitted field to null (ConvertEmptyStringToNull), and a
    // blank client secret is a legitimate value (e.g. testing a public client) — coalesce it away.
    private static OAuthClientConfig BuildConfig(OAuthClientConfigInput input) => new()
    {
        AuthorizeEndpoint = input.AuthorizeEndpoint ?? "",
        TokenEndpoint = input.TokenEndpoint ?? "",
        ResourceEndpoint = input.ResourceEndpoint ?? "",
        ClientId = input.ClientId ?? "",
        ClientSecret = input.ClientSecret ?? "",
        RedirectUri = input.RedirectUri ?? "",
        Scope = input.Scope ?? "",
    };

    // Persisted so the values used to kick off /authorize are still there once the browser comes
    // back from the AS at /callback — everything after that is driven by the form's live fields again.
    private void SaveConfig(OAuthClientConfig cfg)
    {
        HttpContext.Session.SetString(CfgAuthorizeEndpointKey, cfg.AuthorizeEndpoint);
        HttpContext.Session.SetString(CfgTokenEndpointKey, cfg.TokenEndpoint);
        HttpContext.Session.SetString(CfgResourceEndpointKey, cfg.ResourceEndpoint);
        HttpContext.Session.SetString(CfgClientIdKey, cfg.ClientId);
        HttpContext.Session.SetString(CfgClientSecretKey, cfg.ClientSecret);
        HttpContext.Session.SetString(CfgRedirectUriKey, cfg.RedirectUri);
        HttpContext.Session.SetString(CfgScopeKey, cfg.Scope);
    }

    private void StoreTokens(TokenResponse? token)
    {
        if (token?.AccessToken is null)
        {
            return;
        }

        HttpContext.Session.SetString(AccessTokenKey, token.AccessToken);
        HttpContext.Session.SetString(ScopeKey, token.Scope ?? "");
        HttpContext.Session.SetString(TokenTypeKey, token.TokenType ?? "");

        if (token.ExpiresIn is not null)
        {
            HttpContext.Session.SetString(ExpiresInKey, token.ExpiresIn.Value.ToString());
        }

        if (token.RefreshToken is not null)
        {
            HttpContext.Session.SetString(RefreshTokenKey, token.RefreshToken);
        }
    }

    private ClientViewModel BuildViewModel() => new()
    {
        Config = GetEffectiveConfig(),
        State = HttpContext.Session.GetString(StateKey),
        Code = HttpContext.Session.GetString(CodeKey),
        AccessToken = HttpContext.Session.GetString(AccessTokenKey),
        TokenType = HttpContext.Session.GetString(TokenTypeKey),
        ExpiresIn = HttpContext.Session.GetString(ExpiresInKey),
        RefreshToken = HttpContext.Session.GetString(RefreshTokenKey),
        Scope = HttpContext.Session.GetString(ScopeKey),
        Error = TempData["Error"] as string,
        Logs = GetLogs(),
    };

    private void AppendLog(LogEntry entry)
    {
        entry.Time = DateTimeOffset.Now.ToString("T");
        var logs = GetLogs();
        logs.Add(entry);
        HttpContext.Session.SetString(LogKey, JsonSerializer.Serialize(logs));
    }

    private List<LogEntry> GetLogs()
    {
        var json = HttpContext.Session.GetString(LogKey);
        if (string.IsNullOrEmpty(json))
        {
            return [];
        }

        return JsonSerializer.Deserialize<List<LogEntry>>(json) ?? [];
    }

    private static Dictionary<string, string> MergeHeaders(HttpHeaders headers, HttpHeaders? contentHeaders)
    {
        var result = new Dictionary<string, string>();
        foreach (var header in headers)
        {
            result[header.Key] = string.Join(", ", header.Value);
        }

        if (contentHeaders is not null)
        {
            foreach (var header in contentHeaders)
            {
                result[header.Key] = string.Join(", ", header.Value);
            }
        }

        return result;
    }

    private static string? FormatJson(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
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

    private static TokenResponse? Deserialize(string json)
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

    private static string RandomToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
}
