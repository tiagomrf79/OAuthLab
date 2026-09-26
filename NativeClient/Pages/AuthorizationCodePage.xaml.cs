using System.Net.Http.Headers;
using System.Net.Http.Json;
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
    // Client ID/secret are left blank — this client has no static credentials baked in; it
    // registers itself dynamically (RFC 7591) the first time it starts an authorization request.
    private void LoadDefaults()
    {
        RegisterEndpointEntry.Text = "http://10.0.2.2:5001/register";
        AuthorizeEndpointEntry.Text = "http://10.0.2.2:5001/authorize";
        TokenEndpointEntry.Text = "http://10.0.2.2:5001/token";
        ResourceEndpointEntry.Text = "http://10.0.2.2:5002";
        ClientIdEntry.Text = "";
        ClientSecretEntry.Text = "";
        RedirectUriEntry.Text = "nativeclient://callback";
        ScopeEntry.Text = "read write delete";
    }

    // RFC 7591 dynamic client registration: a real install would do this once on first launch and
    // persist the result; here it happens lazily, the first time a token is needed and no
    // client_id is on hand yet, which keeps the demo to a single "Start Authorization Request" tap.
    private async Task<bool> RegisterClientAsync()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, RegisterEndpointEntry.Text)
        {
            Content = JsonContent.Create(new ClientRegistrationRequest
            {
                RedirectUris = [RedirectUriEntry.Text ?? ""],
                ClientName = "Native Client",
                Scope = ScopeEntry.Text ?? "",
                // Explicit rather than relying on the server's defaults — this page's "Refresh
                // Access Token" button needs refresh_token too, not just authorization_code.
                TokenEndpointAuthMethod = "client_secret_basic",
                GrantTypes = ["authorization_code", "refresh_token"],
                ResponseTypes = ["code"],
            }),
        };

        var (response, body, log) = await _oauth.SendAndLogAsync("Register client (dynamic client registration)", request);
        AppendLog(log);

        if (!response.IsSuccessStatusCode)
        {
            SetError("Dynamic client registration failed — see the log below.");
            return false;
        }

        var registration = OAuthService.DeserializeRegistration(body);
        if (registration?.ClientId is null)
        {
            SetError("Dynamic client registration succeeded but returned no client_id.");
            return false;
        }

        ClientIdEntry.Text = registration.ClientId;
        ClientSecretEntry.Text = registration.ClientSecret ?? "";
        return true;
    }

    private async void OnStartAuthorizationClicked(object? sender, EventArgs e)
    {
        SetError(null);

        if (string.IsNullOrEmpty(ClientIdEntry.Text) && !await RegisterClientAsync())
        {
            return;
        }

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
        var authorizeUrl = OAuthService.BuildUrl(AuthorizeEndpointEntry.Text ?? "", query);

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
}
