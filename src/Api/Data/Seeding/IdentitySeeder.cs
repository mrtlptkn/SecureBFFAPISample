using Api.Identity;
using Contracts;
using Microsoft.AspNetCore.Identity;

namespace Api.Data.Seeding;

/// <summary>
/// Roller ve izin claim'lerini oluşturur. Admin rolü tüm izinlere sahiptir,
/// User rolü yalnızca products.read alır. Admin kullanıcısı Seed:* ayarlarından oluşturulur.
/// </summary>
public static class IdentitySeeder
{
    public const string AdminRole = "Admin";
    public const string UserRole = "User";

    public static async Task SeedAsync(IServiceProvider services, IConfiguration config)
    {
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Seeder");

        await EnsureRoleAsync(roleManager, AdminRole, Permissions.All);
        await EnsureRoleAsync(roleManager, UserRole, [Permissions.Products.Read]);

        var adminEmail = config["Seed:AdminEmail"];
        var adminPassword = config["Seed:AdminPassword"];

        if (string.IsNullOrWhiteSpace(adminEmail) || string.IsNullOrWhiteSpace(adminPassword))
        {
            logger.LogWarning("Seed:AdminEmail veya Seed:AdminPassword tanımlı değil. Admin kullanıcısı oluşturulmadı.");
            return;
        }

        if (await userManager.FindByEmailAsync(adminEmail) is not null)
            return;

        var admin = new ApplicationUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true
        };

        var created = await userManager.CreateAsync(admin, adminPassword);
        if (!created.Succeeded)
        {
            throw new InvalidOperationException(
                "Admin kullanıcısı oluşturulamadı: " + string.Join(", ", created.Errors.Select(e => e.Description)));
        }

        await userManager.AddToRoleAsync(admin, AdminRole);
        logger.LogInformation("Admin kullanıcısı oluşturuldu: {Email}", adminEmail);
    }

    private static async Task EnsureRoleAsync(
        RoleManager<IdentityRole<Guid>> roleManager,
        string roleName,
        IEnumerable<string> permissions)
    {
        var role = await roleManager.FindByNameAsync(roleName);
        if (role is null)
        {
            role = new IdentityRole<Guid>(roleName);
            var created = await roleManager.CreateAsync(role);
            if (!created.Succeeded)
                throw new InvalidOperationException($"'{roleName}' rolü oluşturulamadı.");
        }

        var existing = await roleManager.GetClaimsAsync(role);

        foreach (var permission in permissions)
        {
            var alreadyAssigned = existing.Any(c => c.Type == Permissions.ClaimType && c.Value == permission);
            if (!alreadyAssigned)
                await roleManager.AddClaimAsync(role, new System.Security.Claims.Claim(Permissions.ClaimType, permission));
        }
    }
}
