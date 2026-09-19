using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using ConfidentialClient.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using static ConfidentialClient.Controllers.SessionKeys.Config;
using static ConfidentialClient.Controllers.SessionKeys.OAuth;

namespace ConfidentialClient.Controllers;

public class HomeController(IHttpClientFactory httpClientFactory, IConfiguration config) : Controller
{
    [HttpGet("/")]
    public IActionResult Index()
    {
        return View();
    }

    [HttpGet("/authorization-code")]
    public IActionResult AuthorizationCode()
    {
        return View(BuildViewModel());
    }

    [HttpPost("/authorize")]
    public IActionResult Authorize(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);
        ClearOAuthSession();

        var state = GenerateState();
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
            return RedirectToAction(nameof(AuthorizationCode));
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
            return RedirectToAction(nameof(AuthorizationCode));
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

        return RedirectToAction(nameof(AuthorizationCode));
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
            return RedirectToAction(nameof(AuthorizationCode));
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

        return RedirectToAction(nameof(AuthorizationCode));
    }

    [HttpPost("/refresh_token")]
    public async Task<IActionResult> RefreshToken(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        await RefreshAccessTokenAsync(cfg);
        return RedirectToReturnPage(input.ReturnTo);
    }

    [HttpGet("/password")]
    public IActionResult Password()
    {
        return View(BuildViewModel());
    }

    [HttpPost("/password_token")]
    public async Task<IActionResult> PasswordToken(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        var request = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = cfg.Username,
                ["password"] = cfg.Password,
                ["scope"] = cfg.Scope,
            }),
        };
        request.Headers.Authorization = BasicAuthHeader(cfg);

        var (response, body) = await SendAndLogAsync("Request access token (resource owner password credentials)", request);
        if (response.IsSuccessStatusCode)
        {
            StoreTokens(Deserialize(body));
        }

        return RedirectToAction(nameof(Password));
    }

    [HttpGet("/client-credentials")]
    public IActionResult ClientCredentials()
    {
        return View(BuildViewModel());
    }

    [HttpPost("/client_credentials_token")]
    public async Task<IActionResult> ClientCredentialsToken(OAuthClientConfigInput input)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        var request = new HttpRequestMessage(HttpMethod.Post, cfg.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["scope"] = cfg.Scope,
            }),
        };
        request.Headers.Authorization = BasicAuthHeader(cfg);

        var (response, body) = await SendAndLogAsync("Request access token (client credentials)", request);
        if (response.IsSuccessStatusCode)
        {
            StoreTokens(Deserialize(body));
        }

        return RedirectToAction(nameof(ClientCredentials));
    }

    [HttpPost("/fetch_resource")]
    public async Task<IActionResult> FetchResource(OAuthClientConfigInput input, string? operation)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);

        var op = NormalizeOperation(operation);
        await CallResourceAsync(cfg, op, $"Call protected resource ({op})");
        return RedirectToReturnPage(input.ReturnTo);
    }

    [HttpPost("/fetch_resource_auto")]
    public async Task<IActionResult> FetchResourceAuto(OAuthClientConfigInput input, string? operation)
    {
        var cfg = BuildConfig(input);
        SaveConfig(cfg);
        var op = NormalizeOperation(operation);

        var (initialResponse, _) = await CallResourceAsync(cfg, op, $"Call protected resource ({op}, auto)");
        if (initialResponse.StatusCode != System.Net.HttpStatusCode.Unauthorized)
        {
            return RedirectToReturnPage(input.ReturnTo);
        }

        if (!await RefreshAccessTokenAsync(cfg))
        {
            return RedirectToReturnPage(input.ReturnTo);
        }

        var (retryResponse, _) = await CallResourceAsync(cfg, op, $"Call protected resource ({op}, retry after refresh)");
        if (!retryResponse.IsSuccessStatusCode)
        {
            TempData["Error"] = "Resource call still failed after refreshing the access token.";
        }

        return RedirectToReturnPage(input.ReturnTo);
    }

    [HttpGet("/reset")]
    public IActionResult Reset(string? returnTo)
    {
        ClearOAuthSession();
        return RedirectToReturnPage(returnTo);
    }

    [HttpGet("/clear_log")]
    public IActionResult ClearLog(string? returnTo)
    {
        HttpContext.Session.Remove(LogKey);
        return RedirectToReturnPage(returnTo);
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

    private IActionResult RedirectToReturnPage(string? returnTo) => returnTo switch
    {
        nameof(ClientCredentials) => RedirectToAction(nameof(ClientCredentials)),
        nameof(Password) => RedirectToAction(nameof(Password)),
        _ => RedirectToAction(nameof(AuthorizationCode)),
    };

    private void ClearOAuthSession()
    {
        HttpContext.Session.Remove(StateKey);
        HttpContext.Session.Remove(CodeKey);
        ClearTokens();
    }

    private void ClearTokens()
    {
        foreach (var key in new[] { AccessTokenKey, TokenTypeKey, ExpiresInKey, RefreshTokenKey, ScopeKey })
        {
            HttpContext.Session.Remove(key);
        }
    }

    // Each scope maps to its own sub-path and HTTP verb on the resource server (read/GET,
    // write/POST, delete/DELETE) — see ProtectedResource/Program.cs.
    private static readonly Dictionary<string, HttpMethod> OperationMethods = new()
    {
        ["read"] = HttpMethod.Get,
        ["write"] = HttpMethod.Post,
        ["delete"] = HttpMethod.Delete,
    };

    private static string NormalizeOperation(string? operation) =>
        operation is not null && OperationMethods.ContainsKey(operation) ? operation : "read";

    private Task<(HttpResponseMessage Response, string Body)> CallResourceAsync(OAuthClientConfig cfg, string operation, string title)
    {
        var accessToken = HttpContext.Session.GetString(AccessTokenKey);
        var request = new HttpRequestMessage(OperationMethods[operation], $"{cfg.ResourceEndpoint}/{operation}");
        if (!string.IsNullOrEmpty(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        return SendAndLogAsync(title, request);
    }

    private async Task<bool> RefreshAccessTokenAsync(OAuthClientConfig cfg)
    {
        var refreshToken = HttpContext.Session.GetString(RefreshTokenKey);
        if (!string.IsNullOrEmpty(refreshToken))
        {
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
                return true;
            }
        }

        ClearTokens();
        TempData["Error"] = "Unable to refresh the access token — please Authorize again.";
        return false;
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
        Username = GetSetting(CfgUsernameKey, "ResourceOwner:Username"),
        Password = GetSetting(CfgPasswordKey, "ResourceOwner:Password"),
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
        Username = input.Username ?? "",
        Password = input.Password ?? "",
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
        HttpContext.Session.SetString(CfgUsernameKey, cfg.Username);
        HttpContext.Session.SetString(CfgPasswordKey, cfg.Password);
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

    private static string GenerateState() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
}
