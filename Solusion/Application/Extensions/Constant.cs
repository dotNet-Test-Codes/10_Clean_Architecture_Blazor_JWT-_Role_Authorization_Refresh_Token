namespace Application.Extensions
{
    public static class Constant
    {
        public const string BrowserStorageKey = "x-key";
        public const string AuthenticationType = "JwtAuth";
        public const string HttpClientName = "WebUIClient";
        public const string HttpClientHeaderScheme = "Bearer";

        public const string CreateAdminRoute = "setting";
        public const string LoginRoute = "api/account/identity/login";
        public const string RegisterRoute = "api/account/identity/create";
        public const string GetRolesRoute = "api/account/identity/roles/list";
        public const string CreateRoleRoute = "api/account/identity/role/create";
        public const string RefreshTokenRoute = "api/account/identity/refresh-token";
        public const string ChangeUsersRoleRoute = "api/account/identity/change-role";
        public const string GetUserWithRolesRoute = "api/account/identity/users-with-roles";

        public static class Role
        {
            public const string Admin = "Admin";
            public const string User = "User";
        }
    }
}
