using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Http.Resilience;
using Web.Auth;
using Web.Handlers;
using Web.Middleware;
using Web.Resilience;
using Web.Services;

var builder = WebApplication.CreateBuilder(args);

var apiBaseUrl = new Uri(builder.Configuration["Api:BaseUrl"] ?? "http://localhost:5100");
var resilience = builder.Configuration.GetSection(ResilienceOptions.SectionName).Get<ResilienceOptions>()
                 ?? new ResilienceOptions();

builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();  // Bu projede kullanmamızın sebebi AccessTokenHandler servisi içerisinde HttpContext bilgilerine erişmek istiyoruz.

// Oturum token'ları sunucuda tutulur. Geliştirmede bellek; üretimde Redis kullanın.
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton<ServerTokenStore>(); // ServerTokenStore, access ve refresh token'ları tarayıcıdan ayırıp sunucuda tutmak için kullanılıyor. Cookie'de yalnızca sid adlı opak bir kimlik bulunuyor. Token'lar IDistributedCache içinde session:{sid} anahtarıyla saklanıyor
builder.Services.AddSingleton<AuthApiClient>();
builder.Services.AddScoped<ApiClient>();
builder.Services.AddTransient<AccessTokenHandler>(); //  API'ye giden her istek bu handler'dan geçerek access token'ı ekler.

// Kimlik işlemleri: retry yok, circuit breaker + timeout
builder.Services.AddHttpClient("auth", c => c.BaseAddress = apiBaseUrl)
    .AddResilienceHandler("auth", (pipeline, _) =>
        ResiliencePolicies.ConfigureNoRetryPipeline(pipeline, resilience));

// Okuma: token ekleme + retry (yalnızca GET) + circuit breaker + timeout
builder.Services.AddHttpClient("api-read", c => c.BaseAddress = apiBaseUrl)
    .AddHttpMessageHandler<AccessTokenHandler>()
    .AddResilienceHandler("api-read", (pipeline, _) =>
        ResiliencePolicies.ConfigureReadPipeline(pipeline, resilience));

// Yazma: token ekleme + circuit breaker + timeout (retry yok)
builder.Services.AddHttpClient("api-write", c => c.BaseAddress = apiBaseUrl)
    .AddHttpMessageHandler<AccessTokenHandler>()
    .AddResilienceHandler("api-write", (pipeline, _) =>
        ResiliencePolicies.ConfigureNoRetryPipeline(pipeline, resilience));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o => CookieAuthConfig.Configure(o));

builder.Services.AddAuthorization(o => o.AddPermissionPolicies());

// BFF girişinde IP bazlı sınır (gerçek istemci IP'si burada görünür)
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("bff-auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));
});

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseMiddleware<SessionErrorMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

app.Run();
