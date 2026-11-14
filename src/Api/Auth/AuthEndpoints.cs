using System.Security.Claims;
using Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using System.Threading.RateLimiting;

namespace Api.Auth;

public static class AuthEndpoints
{
    public static RouteGroupBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/register", async (RegisterRequest request, AuthService auth, CancellationToken ct) =>
                (await auth.RegisterAsync(request, ct)).ToHttpResult())
            .RequireRateLimiting("auth-register");

        group.MapPost("/login", async (
                LoginRequest request,
                HttpContext http,
                AuthService auth,
                EmailRateLimiter emailLimiter,
                CancellationToken ct) =>
            {
                // Hesap bazlı sınır: aynı e-postaya farklı IP'lerden gelen denemeleri de sayar
                using var lease = await emailLimiter.AcquireAsync(request.Email, ct);
              //  Pencerede hak kalmadı, deneme reddedilmeli.
              if (!lease.IsAcquired)
                {
                    // Gerçek bekleme süresi limiter'dan okunur 
                    // İlk deneme 09:00, 6.deneme reddedilme 09:03 Pencerenin bitmesine 12 dakika kaldı, bu gerçek değeri döner. 09:15 de yeni denemeler denenebilir.  
                    var retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out var ra)
                        ? ra
                        : TimeSpan.FromMinutes(15);
                    http.Response.Headers["Retry-After"] =
                        ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                    return Results.Problem(
                        title: "Çok fazla deneme yapıldı. Lütfen daha sonra tekrar deneyin.",
                        statusCode: StatusCodes.Status429TooManyRequests);
                }

                return (await auth.LoginAsync(request, ct)).ToHttpResult();
            })
            .RequireRateLimiting("auth-login");

        group.MapPost("/refresh", async (RefreshRequest request, AuthService auth, CancellationToken ct) =>
                (await auth.RefreshAsync(request, ct)).ToHttpResult())
            .RequireRateLimiting("auth-refresh");

        // Refresh token ile çalışır; access token süresi dolmuş olsa bile çıkış yapılabilmeli
        group.MapPost("/logout", async (LogoutRequest request, AuthService auth, CancellationToken ct) =>
        {
            await auth.LogoutAsync(request.RefreshToken, ct);
            return Results.NoContent();
        });

        group.MapGet("/me", async (ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
                (await auth.GetMeAsync(user, ct)).ToHttpResult())
            .RequireAuthorization();

        return group;
    }
}
