using Api.Identity;
using Contracts;
using Microsoft.AspNetCore.Identity;

namespace Api.Auth;

/// <summary>
/// Kullanıcının etkin izinlerini hesaplar: rollerden gelen izinler ile kullanıcıya özel izinlerin birleşimi.
/// Bilinmeyen izinler (Permissions.All içinde olmayanlar) filtrelenir.
/// </summary>
public sealed class PermissionService(
    UserManager<ApplicationUser> users,
    RoleManager<IdentityRole<Guid>> roles)
{
    public async Task<IReadOnlyList<string>> GetPermissionsAsync(ApplicationUser user)
    {
        var permissions = new HashSet<string>(StringComparer.Ordinal);

        foreach (var roleName in await users.GetRolesAsync(user))
        {
            var role = await roles.FindByNameAsync(roleName);
            if (role is null)
                continue;

            foreach (var claim in await roles.GetClaimsAsync(role))
            {
                if (claim.Type == Permissions.ClaimType)
                    permissions.Add(claim.Value);
            }
        }

        foreach (var claim in await users.GetClaimsAsync(user))
        {
            if (claim.Type == Permissions.ClaimType)
                permissions.Add(claim.Value);
        }

        return permissions
            .Where(p => Permissions.All.Contains(p))
            .Order()
            .ToList();
    }
}
