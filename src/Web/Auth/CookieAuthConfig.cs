using System.Security.Claims;
using Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Web.Services;

namespace Web.Auth;

public static class CookieAuthConfig
{
    public static void Configure(CookieAuthenticationOptions options)
    {
        options.Cookie.Name = "__Host-bff";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.Path = "/";

        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = false;

        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Home/Forbidden";

        options.Events.OnValidatePrincipal = ValidateAsync;
    }

    /// <summary>
    /// Her istekte çalışır. Oturum sunucudan silinmişse (refresh başarısız, zorla çıkış) cookie reddedilir.
    /// Yetkiler oturumdan okunur, böylece yenilemeden sonra değişen izinler MVC tarafına da yansır.
    /// </summary>
    private static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var sid = context.Principal?.FindFirst(SessionClaims.Sid)?.Value;

        var store = context.HttpContext.RequestServices.GetRequiredService<ServerTokenStore>();
        var session = sid is null
            ? null
            : await store.GetAsync(sid, context.HttpContext.RequestAborted);

        if (session is null)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return;
        }

        var identity = context.Principal!.Identities.First();
        foreach (var existing in identity.FindAll(Permissions.ClaimType).ToList())
            identity.RemoveClaim(existing);

        foreach (var permission in session.Permissions)
            identity.AddClaim(new Claim(Permissions.ClaimType, permission));
    }
}
