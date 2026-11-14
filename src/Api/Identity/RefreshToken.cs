namespace Api.Identity;

/// <summary>
/// Refresh token'ın yalnızca SHA-256 hash'i saklanır. FamilyId, rotasyon zincirini temsil eder;
/// zincirdeki eski bir token tekrar kullanılırsa tüm aile iptal edilir.
/// </summary>
public sealed class RefreshToken
{
    /// <summary>Refresh token kaydının benzersiz kimliği (birincil anahtar).</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Token'ın ait olduğu kullanıcının kimliği.</summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Rotasyon zincirinin kimliği. Login'de üretilir, her refresh'te korunur.
    /// Reuse tespit edildiğinde aynı aileye ait tüm token'lar birlikte iptal edilir.
    /// </summary>
    public Guid FamilyId { get; set; }

    /// <summary>Ham refresh token'ın SHA-256 hash'i (Base64). Ham token veritabanında saklanmaz.</summary>
    public required string TokenHash { get; set; }

    /// <summary>Token'ın oluşturulma zamanı (UTC).</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Token'ın son geçerlilik zamanı. Bu zaman geçmişse token kullanılamaz.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Token'ın iptal zamanı. Null ise token aktiftir. Rotasyon, logout veya aile/kullanıcı iptali sırasında doldurulur.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>İptal nedeni (ör. "rotated", "reuse-detected", "logout", "user-invalid", "user-disabled", "force-logout").</summary>
    public string? RevokeReason { get; set; }
}
