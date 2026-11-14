using System.Security.Claims;
using Api.Identity;
using Contracts;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;

namespace Api.Auth;

/// <summary>
/// Her istekte çalışır. Token'daki security_stamp, DB'deki güncel değerle eşleşmiyorsa
/// veya kullanıcı devre dışıysa token reddedilir. Bu sayede yetki değişiklikleri anında etkili olur.
/// </summary>
public static class SecurityStampValidator
{
    /// <summary>
    /// JWT doğrulandıktan sonra çağrılır. Token'daki "sub" claim'i geçerli bir Guid değilse token reddedilir.
    /// Geçerliyse kullanıcı veritabanından yeniden yüklenir; kullanıcı yoksa, devre dışıysa veya
    /// token'daki security_stamp değeri DB'deki güncel değerle eşleşmiyorsa context.Fail ile token reddedilir.
    /// </summary>
    /// <param name="context">Token doğrulama bağlamı; principal'a ve reddetme işlemine bu üzerinden erişilir.</param>
    public static async Task ValidateAsync(TokenValidatedContext context)
    {
        var principal = context.Principal;
        var subject = principal?.FindFirst("sub")?.Value;
        var tokenStamp = principal?.FindFirst(Permissions.SecurityStampClaimType)?.Value;

        if (!Guid.TryParse(subject, out var userId))
        {
            context.Fail("Geçersiz token konusu.");
            return;
        }

        var users = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId.ToString());

        if (user is null || user.IsDisabled || user.SecurityStamp != tokenStamp)
        {
            context.Fail("Token artık geçerli değil.");
        }
    }
}
