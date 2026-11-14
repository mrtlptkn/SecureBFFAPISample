using Contracts;
using Microsoft.AspNetCore.Authorization;

namespace Web.Auth;

public static class PermissionPolicies
{
    /// <summary>
    /// MVC tarafında da aynı izin adlarıyla policy kaydeder. Bu kontroller yalnızca arayüzü yönlendirir;
    /// asıl yetki kontrolü API'de yapılır.
    /// </summary>
    public static void AddPermissionPolicies(this AuthorizationOptions options)
    {
        foreach (var permission in Permissions.All)
        {
            options.AddPolicy(permission, policy => policy
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, permission));
        }
    }
}
