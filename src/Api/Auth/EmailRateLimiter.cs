using System.Threading.RateLimiting;

namespace Api.Auth;

/// <summary>
/// Hesap bazlı (e-posta) deneme sınırı. IP bazlı sınır ayrı policy ile uygulanır.
/// Aynı hesaba farklı IP'lerden yapılan brute force denemelerini de yakalar.
/// </summary>
public sealed class EmailRateLimiter : IDisposable
{
  //  PartitionedRateLimiter<string>, .NET'in System.Threading.RateLimiting kütüphanesinden bir sınırlayıcıdır. Tek bir sayaç yerine her anahtar için ayrı bir sınırlayıcı (partition) tutar. Bu kodda anahtar, normalize edilmiş e-posta adresidir:
  //  Yani her e-posta adresinin kendi penceresi vardır: 15 dakikada en fazla 5 deneme. Bir hesaba yapılan denemeler başka bir hesabı etkilemez.
  private readonly PartitionedRateLimiter<string> _limiter; 

    public EmailRateLimiter()
    {
        _limiter = PartitionedRateLimiter.Create<string, string>(email =>
            RateLimitPartition.GetFixedWindowLimiter(
                // Null/boş e-posta NullReferenceException yerine ortak bir bölüme düşer
                (email ?? string.Empty).Trim().ToUpperInvariant(),
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 5,
                    Window = TimeSpan.FromMinutes(15), 
                    QueueLimit = 0,
                    AutoReplenishment = true // AutoReplenishment = true, pencere süresi dolduğunda sayacın kendiliğinden sıfırlanmasını sağlar
                                             // Sınır kalıcı kalmaz. Hesap bir kez 5 denemeye ulaştığında 15 dakika sonra yeniden deneme hakkı açılır
                }));
    }

    public ValueTask<RateLimitLease> AcquireAsync(string email, CancellationToken ct) =>
        _limiter.AcquireAsync(email, 1, ct);

    public void Dispose() => _limiter.Dispose();
}
