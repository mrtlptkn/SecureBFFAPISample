using System.Text;
using System.Threading.RateLimiting;
using Api.Auth;
using Api.Data;
using Api.Data.Seeding;
using Api.Endpoints;
using Api.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ---------- Ayarlar ----------
var jwtSection = builder.Configuration.GetSection(JwtOptions.SectionName);
var jwt = jwtSection.Get<JwtOptions>() ?? new JwtOptions();

if (Encoding.UTF8.GetByteCount(jwt.Key) < 32)
{
    throw new InvalidOperationException(
        "Jwt:Key en az 32 byte olmalı. 'dotnet user-secrets set \"Jwt:Key\" \"...\"' ile ayarlayın.");
}

builder.Services.Configure<JwtOptions>(jwtSection);

// ---------- Veritabanı (SQLite, dosya tabanlı) ----------
var contentRoot = builder.Environment.ContentRootPath;
Directory.CreateDirectory(Path.Combine(contentRoot, "App_Data"));

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? $"Data Source={Path.Combine(contentRoot, "App_Data", "app.db")}";

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite(connectionString));

// ---------- ASP.NET Core Identity ----------
builder.Services.AddIdentityCore<ApplicationUser>(o =>
    {
        o.Password.RequiredLength = 8;
        o.Password.RequireNonAlphanumeric = false;
        o.User.RequireUniqueEmail = true;

        // Hesap bazlı brute force koruması: 5 başarısız denemeden sonra 15 dakika kilit
        o.Lockout.AllowedForNewUsers = true;
        o.Lockout.MaxFailedAccessAttempts = 5;
        o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>();

// ---------- Uygulama servisleri ----------
builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddScoped<RefreshTokenService>();
builder.Services.AddScoped<PermissionService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AccountSecurityService>();
builder.Services.AddSingleton<EmailRateLimiter>();

// ---------- JWT doğrulama + security stamp kontrolü ----------
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        // "sub", "permission", "security_stamp" claim adları olduğu gibi kalsın
        o.MapInboundClaims = false;

        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        o.Events = new JwtBearerEvents
        {
            OnTokenValidated = Api.Auth.SecurityStampValidator.ValidateAsync
        };
    });

// Her izin için bir policy (ör. RequireAuthorization("products.read"))
builder.Services.AddAuthorization(o => o.AddPermissionPolicies());

// ---------- Rate limiting (IP bazlı) ----------
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.OnRejected = (context, _) =>
    {
        context.HttpContext.Response.Headers["Retry-After"] = "60";
        return ValueTask.CompletedTask;
    };

    o.AddPolicy("auth-login", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ClientIp(ctx), // IP adresi kısıtlaması
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 20, //  Her IP adresi dakikada en fazla 20 login denemesi yapabilir.
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));

    o.AddPolicy("auth-refresh", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ClientIp(ctx), // IP adresi kısıtlaması
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 30,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));

    o.AddPolicy("auth-register", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ClientIp(ctx), // IP adresi kısıtlaması
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 5,
            Window = TimeSpan.FromHours(1),
            QueueLimit = 0
        }));
});

var app = builder.Build();

// ---------- Migration ve seed ----------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
    await IdentitySeeder.SeedAsync(scope.ServiceProvider, builder.Configuration);
}

// ---------- Pipeline ----------
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapProfileEndpoints();
app.MapProductEndpoints();
app.MapAdminEndpoints();

app.Run();

static string ClientIp(HttpContext context) =>
    context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
