using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Polly.CircuitBreaker;
using Web.Auth;

namespace Web.Middleware;

/// <summary>
/// Oturum sona erdiğinde ve API devre kesicisi açıkken kullanıcıyı uygun sayfalara yönlendirir.
/// </summary>
public sealed class SessionErrorMiddleware(RequestDelegate next, ILogger<SessionErrorMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (SessionExpiredException)
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            context.Response.Redirect("/Account/Login?expired=true");
        }
        catch (BrokenCircuitException ex)
        {
            logger.LogWarning(ex, "API devre kesici açık; kullanıcı bakım sayfasına yönlendirildi.");
            context.Response.Redirect("/Home/ServiceUnavailable");
        }
    }
}
