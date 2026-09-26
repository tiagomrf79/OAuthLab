using NativeClient.Pages;

namespace NativeClient;

public partial class AppShell : Shell
{
	public AppShell()
	{
		InitializeComponent();

		// Registered here rather than as ShellContent so it doesn't show up in the flyout —
		// each grant-type screen is reached via a button on MainPage instead. Future grant
		// screens (client credentials, password, dynamic registration) register the same way.
		Routing.RegisterRoute(nameof(AuthorizationCodePage), typeof(AuthorizationCodePage));
		Routing.RegisterRoute(nameof(AuthorizationCodePkcePage), typeof(AuthorizationCodePkcePage));
	}
}
