using System.Security.Cryptography;
using System.Text;
using Api.Data;
using Api.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Api.Auth;

public sealed record RefreshRotationResult(bool Succeeded, Guid UserId, Guid FamilyId)
{
    public static readonly RefreshRotationResult Invalid = new(false, Guid.Empty, Guid.Empty);
}

public sealed record IssuedRefreshToken(string Token, DateTimeOffset ExpiresAt);

public sealed class RefreshTokenService(
    AppDbContext db,
    IOptions<JwtOptions> options,
    ILogger<RefreshTokenService> logger)
{
    private readonly JwtOptions _options = options.Value;

    /// <summary>
    /// Yeni bir refresh token üretir, yalnızca hash'ini veritabanına kaydeder ve ham token'ı döndürür.
    /// <paramref name="familyId"/> null ise yeni bir aile başlatılır (login). Değer verilirse token o aileye eklenir (rotasyon).
    /// Son geçerlilik süresi <c>RefreshTokenDays</c> ayarına göre hesaplanır.
    /// </summary>
    public async Task<IssuedRefreshToken> IssueAsync(Guid userId, Guid? familyId, CancellationToken ct)
    {
        var raw = GenerateToken();
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddDays(_options.RefreshTokenDays);

        var family = familyId ?? Guid.NewGuid();

        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = userId,
            FamilyId = family,
            TokenHash = Hash(raw),
            CreatedAt = now,
            ExpiresAt = expires
        });

        await db.SaveChangesAsync(ct);

        logger.LogInformation(
            "Refresh token issued. UserId={UserId} FamilyId={FamilyId} NewFamily={NewFamily} ExpiresAt={ExpiresAt}",
            userId, family, familyId is null, expires);

        return new IssuedRefreshToken(raw, expires);
    }

    /// <summary>
    /// Refresh token'ı tüketir. Token zaten iptal edilmişse yeniden kullanım (reuse) kabul edilir
    /// ve tüm token ailesi iptal edilir.
    /// </summary>
    public async Task<RefreshRotationResult> RotateAsync(string rawToken, CancellationToken ct)
    {
        var hash = Hash(rawToken);
        var token = await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (token is null)
        {
            logger.LogInformation("Refresh token rotation rejected: token not found.");
            return RefreshRotationResult.Invalid;
        }

        if (token.RevokedAt is not null)
        {
            logger.LogInformation(
                "Refresh token reuse detected (token was already revoked with reason {RevokeReason}). UserId={UserId} FamilyId={FamilyId}",
                token.RevokeReason, token.UserId, token.FamilyId);
            await RevokeFamilyAsync(token.FamilyId, "reuse-detected", ct);
            return RefreshRotationResult.Invalid;
        }

        if (token.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            logger.LogInformation(
                "Refresh token rotation rejected: token expired. UserId={UserId} FamilyId={FamilyId} ExpiredAt={ExpiredAt}",
                token.UserId, token.FamilyId, token.ExpiresAt);
            return RefreshRotationResult.Invalid;
        }

        // Atomik iptal: aynı token iki istekte aynı anda gelirse yalnızca biri kazanır
        DateTimeOffset? revokedAt = DateTimeOffset.UtcNow;
        var affected = await db.RefreshTokens
            .Where(t => t.Id == token.Id && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.RevokedAt, revokedAt)
                .SetProperty(t => t.RevokeReason, "rotated"), ct);

        if (affected == 0)
        {
            logger.LogInformation(
                "Refresh token reuse detected (concurrent rotation lost the race). UserId={UserId} FamilyId={FamilyId}",
                token.UserId, token.FamilyId);
            await RevokeFamilyAsync(token.FamilyId, "reuse-detected", ct);
            return RefreshRotationResult.Invalid;
        }

        logger.LogInformation(
            "Refresh token rotated (old token revoked). UserId={UserId} FamilyId={FamilyId}",
            token.UserId, token.FamilyId);

        return new RefreshRotationResult(true, token.UserId, token.FamilyId);
    }

    /// <summary>
    /// Verilen ham token'ın ait olduğu tüm aileyi "logout" nedeniyle iptal eder.
    /// Token bulunamazsa hiçbir işlem yapmaz.
    /// </summary>
    public async Task RevokeByTokenAsync(string rawToken, CancellationToken ct)
    {
        var hash = Hash(rawToken);
        var token = await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (token is null)
        {
            logger.LogInformation("Logout requested but refresh token was not found; nothing to revoke.");
            return;
        }

        await RevokeFamilyAsync(token.FamilyId, "logout", ct);
    }

    /// <summary>
    /// Belirtilen aileye ait, henüz iptal edilmemiş tüm token'ları verilen nedenle iptal eder.
    /// Reuse tespitinde ve kullanıcı geçersiz kılındığında kullanılır.
    /// </summary>
    public async Task RevokeFamilyAsync(Guid familyId, string reason, CancellationToken ct)
    {
        DateTimeOffset? now = DateTimeOffset.UtcNow;
        var revoked = await db.RefreshTokens
            .Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.RevokedAt, now)
                .SetProperty(t => t.RevokeReason, reason), ct);

        logger.LogInformation(
            "Refresh token family revoked. FamilyId={FamilyId} Reason={Reason} RevokedCount={RevokedCount}",
            familyId, reason, revoked);
    }

    /// <summary>
    /// Kullanıcının tüm ailelerindeki, henüz iptal edilmemiş refresh token'ları verilen nedenle iptal eder.
    /// Sert iptal (devre dışı bırakma, zorla çıkış) için kullanılır.
    /// </summary>
    public async Task RevokeAllForUserAsync(Guid userId, string reason, CancellationToken ct)
    {
        DateTimeOffset? now = DateTimeOffset.UtcNow;
        var revoked = await db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.RevokedAt, now)
                .SetProperty(t => t.RevokeReason, reason), ct);

        logger.LogInformation(
            "All refresh tokens of user revoked. UserId={UserId} Reason={Reason} RevokedCount={RevokedCount}",
            userId, reason, revoked);
    }

    /// <summary>64 baytlık kriptografik olarak güvenli rastgele değer üretir ve Base64 olarak döndürür.</summary>
    private static string GenerateToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    /// <summary>Ham token'ın SHA-256 hash'ini Base64 olarak döndürür. Veritabanında yalnızca bu değer tutulur.</summary>
    private static string Hash(string raw) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
}
