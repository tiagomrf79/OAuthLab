namespace ConfidentialClient.Controllers;

internal static class SessionKeys
{
    public static class OAuth
    {
        public const string StateKey = "oauth.state";
        public const string CodeKey = "oauth.code";
        public const string AccessTokenKey = "oauth.access_token";
        public const string TokenTypeKey = "oauth.token_type";
        public const string ExpiresInKey = "oauth.expires_in";
        public const string RefreshTokenKey = "oauth.refresh_token";
        public const string ScopeKey = "oauth.scope";
        public const string LogKey = "oauth.log";
    }

    public static class Config
    {
        public const string CfgAuthorizeEndpointKey = "cfg.authorize_endpoint";
        public const string CfgTokenEndpointKey = "cfg.token_endpoint";
        public const string CfgResourceEndpointKey = "cfg.resource_endpoint";
        public const string CfgClientIdKey = "cfg.client_id";
        public const string CfgClientSecretKey = "cfg.client_secret";
        public const string CfgRedirectUriKey = "cfg.redirect_uri";
        public const string CfgScopeKey = "cfg.scope";
        public const string CfgUsernameKey = "cfg.username";
        public const string CfgPasswordKey = "cfg.password";
    }
}
