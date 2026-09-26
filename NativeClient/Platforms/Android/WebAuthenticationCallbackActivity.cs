using Android.App;
using Android.Content;
using Android.Content.PM;
using Microsoft.Maui.Authentication;

namespace NativeClient;

// Registered for the "nativeclient://callback" redirect URI configured on the AuthorizationServer.
// The OS routes the browser's redirect here instead of back into a web page; WebAuthenticator picks
// it up and resumes the pending AuthenticateAsync call in whichever page started it
// (AuthorizationCodePage or AuthorizationCodePkcePage).
[Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop, Exported = true)]
[IntentFilter(
    [Intent.ActionView],
    Categories = [Intent.CategoryDefault, Intent.CategoryBrowsable],
    DataScheme = "nativeclient",
    DataHost = "callback")]
public class WebAuthenticationCallbackActivity : WebAuthenticatorCallbackActivity
{
}
