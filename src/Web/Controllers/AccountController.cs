using System.Security.Claims;
using Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Polly.CircuitBreaker;
using Web.Auth;
using Web.Models;
using Web.Services;

namespace Web.Controllers;

public sealed class AccountController(
    AuthApiClient auth,
    ServerTokenStore store,
    ILogger<AccountController> logger) : Controller
{
    [HttpGet]
    public IActionResult Login(bool expired = false)
    {
        ViewBag.Expired = expired;
        return View(new LoginForm());
    }

    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("bff-auth")]
    public async Task<IActionResult> Login(LoginForm form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return View(form);

        var result = await auth.LoginAsync(form.Email, form.Password, ct);
        if (!result.IsSuccess)
        {
            ModelState.AddModelError(string.Empty,
                result.StatusCode == StatusCodes.Status429TooManyRequests
                    ? "Çok fazla deneme yapıldı. Lütfen daha sonra tekrar deneyin."
                    : "E-posta veya şifre hatalı.");
            return View(form);
        }

        await SignInAsync(result.Value!, ct);
        return RedirectToAction("Index", "Dashboard");
    }

    [HttpGet]
    public IActionResult Register() => View(new RegisterForm());

    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("bff-auth")]
    public async Task<IActionResult> Register(RegisterForm form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return View(form);

        var result = await auth.RegisterAsync(form.Email, form.Password, ct);
        if (!result.IsSuccess)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Kayıt tamamlanamadı.");
            return View(form);
        }

        TempData["Message"] = "Kayıt tamamlandı. Şimdi giriş yapabilirsiniz.";
        return RedirectToAction(nameof(Login));
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        var sid = User.FindFirst(SessionClaims.Sid)?.Value;
        string? refreshToken = null;

        if (sid is not null)
        {
            refreshToken = (await store.GetAsync(sid, ct))?.RefreshToken;
            await store.RemoveAsync(sid, ct);
        }

        // Yerel oturum önce kapatılır; API çağrısı başarısız olsa bile kullanıcı çıkmış olur
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (refreshToken is not null)
        {
            try
            {
                await auth.LogoutAsync(refreshToken, ct);
            }
            catch (Exception ex) when (ex is HttpRequestException or BrokenCircuitException)
            {
                logger.LogWarning(ex, "API çıkış isteği gönderilemedi.");
            }
        }

        return RedirectToAction(nameof(Login));
    }

    private async Task SignInAsync(TokenResponse tokens, CancellationToken ct)
    {
        // Her girişte yeni oturum kimliği (session fixation'a karşı); eskisi sunucudan silinir
        var previousSid = User.FindFirst(SessionClaims.Sid)?.Value;
        if (previousSid is not null)
            await store.RemoveAsync(previousSid, ct);

        var sid = Guid.NewGuid().ToString("N");
        await store.SaveAsync(sid, SessionTokens.FromResponse(tokens), ct);

        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, tokens.Email),
            new(SessionClaims.Sid, sid)
        };
        claims.AddRange(tokens.Permissions.Select(p => new Claim(Permissions.ClaimType, p)));

        var identity = new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme,
            ClaimTypes.Email,
            Permissions.ClaimType);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = false, AllowRefresh = false });
    }
}
