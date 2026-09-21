using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.Maui.Authentication;
using NativeClient.Models;
using NativeClient.Services;

namespace NativeClient.Pages;

public partial class AuthorizationCodePage : ContentPage
{
    private readonly OAuthService _oauth = new();

    private string? _state;
    private string? _code;
    private string? _accessToken;
    private string? _refreshToken;

    public AuthorizationCodePage()
    {
        InitializeComponent();
        LoadDefaults();
    }

    // Defaults target the Android emulator's loopback alias (10.0.2.2 = the host machine's
    // localhost) — a physical device on the same network would need the host's LAN IP instead.
    private void LoadDefaults()
    {
        AuthorizeEndpointEntry.Text = "http://10.0.2.2:5001/authorize";
        TokenEndpointEntry.Text = "http://10.0.2.2:5001/token";
        ResourceEndpointEntry.Text = "http://10.0.2.2:5002";
        ClientIdEntry.Text = "native-client";
        ClientSecretEntry.Text = "native-client-secret";
        RedirectUriEntry.Text = "nativeclient://callback";
        ScopeEntry.Text = "read write delete";
    }

    private async void OnStartAuthorizationClicked(object? sender, EventArgs e)
    {
        SetError(null);
        _state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        StateLabel.Text = _state;
        _code = null;
        CodeLabel.Text = "—";

        var query = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ClientIdEntry.Text ?? "",
            ["redirect_uri"] = RedirectUriEntry.Text ?? "",
            ["scope"] = ScopeEntry.Text ?? "",
            ["state"] = _state,
        };
        var authorizeUrl = BuildUrl(AuthorizeEndpointEntry.Text ?? "", query);

        try
        {
            var result = await WebAuthenticator.Default.AuthenticateAsync(
                new WebAuthenticatorOptions
                {
                    Url = new Uri(authorizeUrl),
                    CallbackUrl = new Uri(RedirectUriEntry.Text ?? ""),
                });

            result.Properties.TryGetValue("state", out var returnedState);
            if (returnedState != _state)
            {
                AppendLog("Redirect from authorization server — state mismatch",
                    $"expected state: {_state}\nreceived state: {returnedState}");
                SetError("State mismatch on the redirect from the authorization server.");
                return;
            }

            result.Properties.TryGetValue("code", out var code);
            _code = code;
            CodeLabel.Text = _code ?? "—";
            AppendLog("Redirect from authorization server", $"code: {_code}\nstate: {returnedState}");
        }
        catch (TaskCanceledException)
        {
            AppendLog("Authorization request cancelled", "The system browser was closed before completing sign-in.");
        }
        catch (Exception ex)
        {
            AppendLog("Authorization request failed", ex.Message);
            SetError(ex.Message);
        }
    }

    private async void OnExchangeTokenClicked(object? sender, EventArgs e)
    {
        SetError(null);
        if (string.IsNullOrEmpty(_code))
        {
            SetError("No authorization code yet — run \"Start Authorization Request\" first.");
            return;
        }

        var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpointEntry.Text)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = _code,
                ["redirect_uri"] = RedirectUriEntry.Text ?? "",
            }),
        };
        request.Headers.Authorization = OAuthService.BasicAuthHeader(ClientIdEntry.Text ?? "", ClientSecretEntry.Text ?? "");

        var (response, body, log) = await _oauth.SendAndLogAsync("Exchange code for tokens", request);
        AppendLog(log);

        if (response.IsSuccessStatusCode)
        {
            StoreTokens(OAuthService.DeserializeToken(body));
        }
        else
        {
            SetError("Token exchange failed — see the log below.");
        }
    }

    private async void OnRefreshTokenClicked(object? sender, EventArgs e)
    {
        SetError(null);
        if (string.IsNullOrEmpty(_refreshToken))
        {
            SetError("No refresh token yet — exchange the code for tokens first.");
            return;
        }

        var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpointEntry.Text)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = _refreshToken,
            }),
        };
        request.Headers.Authorization = OAuthService.BasicAuthHeader(ClientIdEntry.Text ?? "", ClientSecretEntry.Text ?? "");

        var (response, body, log) = await _oauth.SendAndLogAsync("Refresh access token", request);
        AppendLog(log);

        if (response.IsSuccessStatusCode)
        {
            StoreTokens(OAuthService.DeserializeToken(body));
        }
        else
        {
            SetError("Refresh failed — see the log below.");
        }
    }

    private async void OnCallResourceClicked(object? sender, EventArgs e)
    {
        SetError(null);
        var operation = WriteOperation.IsChecked ? "write" : DeleteOperation.IsChecked ? "delete" : "read";
        var method = operation switch
        {
            "write" => HttpMethod.Post,
            "delete" => HttpMethod.Delete,
            _ => HttpMethod.Get,
        };

        var request = new HttpRequestMessage(method, $"{ResourceEndpointEntry.Text}/{operation}");
        if (!string.IsNullOrEmpty(_accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
        }

        var (response, _, log) = await _oauth.SendAndLogAsync($"Call protected resource ({operation})", request);
        AppendLog(log);

        if (!response.IsSuccessStatusCode)
        {
            SetError("Resource call failed — see the log below.");
        }
    }

    private void OnResetClicked(object? sender, EventArgs e)
    {
        _state = null;
        _code = null;
        _accessToken = null;
        _refreshToken = null;

        StateLabel.Text = "—";
        CodeLabel.Text = "—";
        AccessTokenLabel.Text = "—";
        TokenTypeLabel.Text = "—";
        ExpiresInLabel.Text = "—";
        RefreshTokenLabel.Text = "—";
        SetError(null);
        LogList.Children.Clear();
    }

    private void OnClearLogClicked(object? sender, EventArgs e)
    {
        LogList.Children.Clear();
    }

    private void StoreTokens(TokenResponse? token)
    {
        if (token?.AccessToken is null)
        {
            return;
        }

        _accessToken = token.AccessToken;
        AccessTokenLabel.Text = token.AccessToken;
        TokenTypeLabel.Text = token.TokenType ?? "—";
        ExpiresInLabel.Text = token.ExpiresIn?.ToString() ?? "—";

        if (token.RefreshToken is not null)
        {
            _refreshToken = token.RefreshToken;
            RefreshTokenLabel.Text = token.RefreshToken;
        }
    }

    private void SetError(string? message)
    {
        ErrorLabel.Text = message ?? "";
        ErrorLabel.IsVisible = message is not null;
    }

    private void AppendLog(LogEntry entry) => AppendLog(entry.Title, entry.Detail, entry.Time);

    private void AppendLog(string title, string detail, string? time = null)
    {
        var entryLayout = new VerticalStackLayout { Spacing = 2 };
        entryLayout.Add(new Label { Text = $"{title}  •  {time ?? DateTimeOffset.Now.ToString("T")}", FontAttributes = FontAttributes.Bold });
        entryLayout.Add(new Label { Text = detail, FontFamily = "Courier", FontSize = 12 });

        LogList.Children.Insert(0, new Border
        {
            Padding = 10,
            Content = entryLayout,
        });
    }

    private static string BuildUrl(string baseUrl, Dictionary<string, string> query)
    {
        var pairs = query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}");
        return $"{baseUrl}?{string.Join('&', pairs)}";
    }
}
