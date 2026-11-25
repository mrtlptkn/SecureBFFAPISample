using System.Security.Claims;
using Api.Common;
using Api.Data.Seeding;
using Api.Identity;
using Contracts;
using Microsoft.AspNetCore.Identity;

namespace Api.Auth;

/// <summary>
/// Yönetim işlemleri. İki tür iptal vardır:
///  - Yumuşak iptal (yetki değişikliği): security stamp güncellenir, refresh token'lar korunur.
///    Eski access token bir sonraki istekte reddedilir, BFF refresh ile yeni izinleri alır.
///  - Sert iptal (devre dışı bırakma, zorla çıkış): stamp güncellenir ve tüm refresh token'lar iptal edilir.
/// </summary>
public sealed class AccountSecurityService(
    UserManager<ApplicationUser> users,
    RoleManager<IdentityRole<Guid>> roles,
    RefreshTokenService refreshTokens,
    ILogger<AccountSecurityService> logger)
{
    /// <summary>
    /// Tüm kullanıcıları e-posta adresine göre sıralı şekilde listeler.
    /// </summary>
    /// <returns>Kullanıcıların <see cref="AdminUserDto"/> listesi.</returns>
    public async Task<List<AdminUserDto>> ListUsersAsync()
    {
        var list = new List<AdminUserDto>();
        foreach (var user in users.Users.OrderBy(u => u.Email).ToList())
            list.Add(await ToDtoAsync(user));
        return list;
    }

    /// <summary>
    /// Kullanıcıya belirtilen rolü atar. Kullanıcı zaten bu role sahipse işlem yapılmaz.
    /// Rol gerçekten eklendiyse yetki değişikliği <see cref="SoftInvalidateAsync"/> ile
    /// mevcut access token'lara yansıtılır.
    /// </summary>
    /// <param name="userId">Rol atanacak kullanıcının kimliği.</param>
    /// <param name="role">Atanacak rolün adı.</param>
    /// <returns>Güncel kullanıcı bilgisi; kullanıcı veya rol bulunamazsa 404 durum kodlu hata.</returns>
    public async Task<ServiceResult<AdminUserDto>> AssignRoleAsync(Guid userId, string role)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
            return NotFound<AdminUserDto>("Kullanıcı bulunamadı.");

        if (!await roles.RoleExistsAsync(role))
            return NotFound<AdminUserDto>("Rol bulunamadı.");

        if (!await users.IsInRoleAsync(user, role))
        {
            await users.AddToRoleAsync(user, role);
            await SoftInvalidateAsync(user);
        }

        return ServiceResult<AdminUserDto>.Ok(await ToDtoAsync(user));
    }

    /// <summary>
    /// Kullanıcıdan belirtilen rolü kaldırır. Yöneticinin kendi admin rolünü kaldırmasına
    /// ve sistemdeki son admin kullanıcının rolünün kaldırılmasına izin verilmez.
    /// Rol gerçekten kaldırıldıysa <see cref="SoftInvalidateAsync"/> çağrılır.
    /// </summary>
    /// <param name="actorId">İşlemi yapan yöneticinin kimliği.</param>
    /// <param name="userId">Rolü kaldırılacak kullanıcının kimliği.</param>
    /// <param name="role">Kaldırılacak rolün adı.</param>
    /// <returns>Güncel kullanıcı bilgisi; kural ihlalinde 409, kullanıcı bulunamazsa 404 durum kodlu hata.</returns>
    public async Task<ServiceResult<AdminUserDto>> RemoveRoleAsync(Guid actorId, Guid userId, string role)
    {
        if (actorId == userId && role == IdentitySeeder.AdminRole)
            return ServiceResult<AdminUserDto>.Fail(StatusCodes.Status409Conflict, "Kendi admin rolünüzü kaldıramazsınız.");

        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
            return NotFound<AdminUserDto>("Kullanıcı bulunamadı.");

        if (role == IdentitySeeder.AdminRole && await users.IsInRoleAsync(user, role))
        {
            var admins = await users.GetUsersInRoleAsync(IdentitySeeder.AdminRole);
            if (admins.Count <= 1)
                return ServiceResult<AdminUserDto>.Fail(StatusCodes.Status409Conflict, "Son admin kullanıcının rolü kaldırılamaz.");
        }

        if (await users.IsInRoleAsync(user, role))
        {
            await users.RemoveFromRoleAsync(user, role);
            await SoftInvalidateAsync(user);
        }

        return ServiceResult<AdminUserDto>.Ok(await ToDtoAsync(user));
    }

    /// <summary>
    /// Kullanıcının devre dışı durumunu günceller. Kullanıcı devre dışı bırakılırsa
    /// <see cref="HardInvalidateAsync"/> ile tüm oturumları sonlandırır. Yönetici kendisini
    /// devre dışı bırakamaz.
    /// </summary>
    /// <param name="actorId">İşlemi yapan yöneticinin kimliği.</param>
    /// <param name="userId">Hedef kullanıcının kimliği.</param>
    /// <param name="disabled">Kullanıcının devre dışı bırakılıp bırakılmayacağı.</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>Güncel kullanıcı bilgisi; kendini devre dışı bırakma durumunda 409, kullanıcı bulunamazsa 404 durum kodlu hata.</returns>
    public async Task<ServiceResult<AdminUserDto>> SetDisabledAsync(Guid actorId, Guid userId, bool disabled, CancellationToken ct)
    {
        if (actorId == userId && disabled)
            return ServiceResult<AdminUserDto>.Fail(StatusCodes.Status409Conflict, "Kendinizi devre dışı bırakamazsınız.");

        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
            return NotFound<AdminUserDto>("Kullanıcı bulunamadı.");

        user.IsDisabled = disabled;
        await users.UpdateAsync(user);

        if (disabled)
            await HardInvalidateAsync(user, "user-disabled", ct);

        return ServiceResult<AdminUserDto>.Ok(await ToDtoAsync(user));
    }

    /// <summary>
    /// Kullanıcıyı zorla çıkışa alır. Security stamp güncellenir ve kullanıcının tüm
    /// refresh token'ları iptal edilir.
    /// </summary>
    /// <param name="userId">Çıkışa zorlanacak kullanıcının kimliği.</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>Güncel kullanıcı bilgisi; kullanıcı bulunamazsa 404 durum kodlu hata.</returns>
    public async Task<ServiceResult<AdminUserDto>> ForceLogoutAsync(Guid userId, CancellationToken ct)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
            return NotFound<AdminUserDto>("Kullanıcı bulunamadı.");

        await HardInvalidateAsync(user, "force-logout", ct);
        return ServiceResult<AdminUserDto>.Ok(await ToDtoAsync(user));
    }

    /// <summary>
    /// Sistemdeki tüm rolleri ad sırasına göre listeler. Her rol için yalnızca
    /// <see cref="Permissions.ClaimType"/> tipindeki izin claim'lerini döner.
    /// </summary>
    /// <returns>Rol adları ve izinlerini içeren <see cref="RoleDto"/> listesi.</returns>
    public async Task<List<RoleDto>> ListRolesAsync()
    {
        var result = new List<RoleDto>();
        foreach (var role in roles.Roles.OrderBy(r => r.Name).ToList())
        {
            var perms = (await roles.GetClaimsAsync(role))
                .Where(c => c.Type == Permissions.ClaimType)
                .Select(c => c.Value)
                .ToList();
            result.Add(new RoleDto(role.Name ?? string.Empty, perms));
        }
        return result;
    }

    /// <summary>
    /// Bir rolün izinlerini istenen izin listesiyle eşitler. Yalnızca
    /// <see cref="Permissions.All"/> içinde tanımlı izinler kabul edilir. Fazla izinler
    /// kaldırılır, eksik izinler eklenir. Admin rolünün izinleri değiştirilemez.
    /// Değişiklikten sonra role sahip her kullanıcı için <see cref="SoftInvalidateAsync"/> çağrılır.
    /// </summary>
    /// <param name="roleName">İzinleri güncellenecek rolün adı.</param>
    /// <param name="requested">Role atanması istenen izinler.</param>
    /// <returns>Güncellenmiş rol ve kabul edilen izinler; admin rolünde 409, rol bulunamazsa 404 durum kodlu hata.</returns>
    public async Task<ServiceResult<RoleDto>> SetRolePermissionsAsync(string roleName, IEnumerable<string> requested)
    {
        if (roleName == IdentitySeeder.AdminRole)
            return ServiceResult<RoleDto>.Fail(StatusCodes.Status409Conflict, "Admin rolünün izinleri değiştirilemez.");

        var role = await roles.FindByNameAsync(roleName);
        if (role is null)
            return ServiceResult<RoleDto>.Fail(StatusCodes.Status404NotFound, "Rol bulunamadı.");

        // Yalnızca bilinen izinler kabul edilir
        var desired = requested.Where(p => Permissions.All.Contains(p)).Distinct().ToList();

        var current = (await roles.GetClaimsAsync(role))
            .Where(c => c.Type == Permissions.ClaimType)
            .ToList();

        foreach (var claim in current.Where(c => !desired.Contains(c.Value)))
            await roles.RemoveClaimAsync(role, claim);

        foreach (var permission in desired.Where(p => current.All(c => c.Value != p)))
            await roles.AddClaimAsync(role, new Claim(Permissions.ClaimType, permission));

        foreach (var user in await users.GetUsersInRoleAsync(roleName))
            await SoftInvalidateAsync(user);

        return ServiceResult<RoleDto>.Ok(new RoleDto(roleName, desired));
    }

    /// <summary>
    /// Yumuşak iptal: kullanıcının security stamp değerini günceller ve refresh token'lara dokunmaz.
    /// Amaç, yetki (rol / izin) değişikliğinin mevcut access token'lara yansımasını sağlamaktır:
    /// stamp değiştiği için eski access token bir sonraki istekte reddedilir. Kullanıcının oturumu
    /// düşmez; BFF, süresi dolan veya reddedilen token'ı refresh token ile yenileyip güncel izinleri alır.
    ///
    /// Çağrıldığı yerler:
    ///  - <see cref="AssignRoleAsync"/>: kullanıcıya yeni bir rol eklendiğinde (rol gerçekten değiştiyse).
    ///  - <see cref="RemoveRoleAsync"/>: kullanıcıdan bir rol kaldırıldığında (rol gerçekten değiştiyse).
    ///  - <see cref="SetRolePermissionsAsync"/>: bir rolün izinleri güncellendikten sonra, o role sahip
    ///    her kullanıcı için tek tek (eski izinlerle üretilmiş token'lar geçersiz kılınır).
    /// </summary>
    private async Task SoftInvalidateAsync(ApplicationUser user)
    {
        await users.UpdateSecurityStampAsync(user);
        logger.LogInformation(
            "Soft invalidation: security stamp updated, existing access tokens revoked, refresh tokens kept. UserId={UserId}",
            user.Id);
    }

    /// <summary>
    /// Sert iptal: kullanıcının security stamp değerini günceller VE kullanıcıya ait tüm refresh
    /// token'ları iptal eder. Yumuşak iptalden farkı, oturumun tamamen sonlandırılmasıdır: access token
    /// reddedilir ve BFF yeni token alamadığı için kullanıcı yeniden giriş yapmak zorunda kalır.
    /// <paramref name="reason"/> iptal nedenini (ör. "user-disabled", "force-logout") refresh token
    /// kayıtlarına yazılır; denetim ve sorun giderme için kullanılır.
    ///
    /// Çağrıldığı yerler:
    ///  - <see cref="SetDisabledAsync"/>: kullanıcı devre dışı bırakıldığında (<c>disabled == true</c>),
    ///    neden "user-disabled". Devre dışı bırakma (<c>IsDisabled = true</c>) kaydedildikten sonra çalışır.
    ///  - <see cref="ForceLogoutAsync"/>: yönetici kullanıcıyı zorla çıkışa aldığında, neden "force-logout".
    /// </summary>
    private async Task HardInvalidateAsync(ApplicationUser user, string reason, CancellationToken ct)
    {
        await users.UpdateSecurityStampAsync(user);
        logger.LogInformation(
            "Hard invalidation: security stamp updated, existing access tokens revoked. UserId={UserId} Reason={Reason}",
            user.Id, reason);
        await refreshTokens.RevokeAllForUserAsync(user.Id, reason, ct);
    }

    /// <summary>
    /// <see cref="ApplicationUser"/> nesnesini, rolleri de içeren <see cref="AdminUserDto"/>
    /// nesnesine dönüştürür.
    /// </summary>
    /// <param name="user">Dönüştürülecek kullanıcı.</param>
    /// <returns>Kullanıcı kimliği, e-posta, devre dışı durumu ve rolleri içeren DTO.</returns>
    private async Task<AdminUserDto> ToDtoAsync(ApplicationUser user)
    {
        var roleNames = await users.GetRolesAsync(user);
        return new AdminUserDto(user.Id.ToString(), user.Email ?? string.Empty, user.IsDisabled, roleNames.ToList());
    }

    /// <summary>
    /// Verilen mesajla 404 Not Found durum kodlu bir <see cref="ServiceResult{T}"/> hatası üretir.
    /// </summary>
    /// <typeparam name="T">Sonucun veri tipi.</typeparam>
    /// <param name="message">Hata mesajı.</param>
    /// <returns>404 durum kodlu başarısız sonuç.</returns>
    private static ServiceResult<T> NotFound<T>(string message) =>
        ServiceResult<T>.Fail(StatusCodes.Status404NotFound, message);
}
