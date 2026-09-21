namespace NativeClient;

public partial class MainPage : ContentPage
{
    public MainPage()
    {
        InitializeComponent();
    }

    private async void OnAuthorizationCodeClicked(object? sender, EventArgs e)
    {
        await Shell.Current.GoToAsync(nameof(Pages.AuthorizationCodePage));
    }
}
