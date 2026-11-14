using Contracts;

namespace Api.Auth;

public static class PermissionPolicies
{
    /// <summary>Her izin için aynı isimde bir policy kaydeder. Endpoint'ler RequireAuthorization("products.read") gibi kullanır.</summary>
    public static void AddPermissionPolicies(this Microsoft.AspNetCore.Authorization.AuthorizationOptions options)
    {
        foreach (var permission in Permissions.All)
        {
            options.AddPolicy(permission, policy => policy
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, permission));
        }
    }
}
