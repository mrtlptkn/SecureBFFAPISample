using System.Collections.Concurrent;
using System.Text.Json;
using Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Web.Services;

namespace Web.Auth;

public static class SessionClaims
{
    /// <summary>
    /// Kullanıcı cookie'sinde taşınan claim'in adı. Değeri, sunucudaki <see cref="ServerTokenStore"/> kaydını
    /// bulmak için kullanılan opak bir oturum kimliğidir (sid). Access ve refresh token'lar bu claim'de değildir.
    /// </summary>
    public const string Sid = "sid";
}

/// <summary>
/// Bir oturuma ait sunucu tarafındaki token seti: access token ve refresh token ile bunların son geçerlilik
/// zamanları, kullanıcının e-postası ve izin listesi. Tarayıcı bu nesneyi görmez; yalnızca sunucu kullanır.
/// </summary>
/// <param name="AccessToken">API çağrılarında kullanılan kısa ömürlü token.</param>
/// <param name="AccessTokenExpiresAt">Access token'ın sona erme zamanı (UTC).</param>
/// <param name="RefreshToken">Yeni access token almak için kullanılan token. Her yenilemede değişir.</param>
/// <param name="RefreshTokenExpiresAt">Refresh token'ın sona erme zamanı (UTC). Oturum kaydının ömrü de buna göre belirlenir.</param>
/// <param name="Email">Oturum sahibinin e-posta adresi.</param>
/// <param name="Permissions">Oturum sahibinin izin listesi. Her istekte cookie principal'ına yazılır.</param>
public sealed record SessionTokens(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt,
    string Email,
    IReadOnlyList<string> Permissions)
{
    public static SessionTokens FromResponse(TokenResponse response) =>
        new(
            response.AccessToken,
            response.AccessTokenExpiresAt,
            response.RefreshToken,
            response.RefreshTokenExpiresAt,
            response.Email,
            response.Permissions);
}

/// <summary>
/// Oturum token'larını sunucu tarafında (<see cref="IDistributedCache"/> üzerinde, <c>session:{sid}</c> anahtarıyla)
/// saklar ve yönetir. Access token süresi dolmak üzereyse refresh token ile yeniler. Tarayıcı yalnızca sid'i taşır.
/// </summary>
public sealed class ServerTokenStore(IDistributedCache cache, AuthApiClient auth)
{
    /// <summary>
    /// Oturum (sid) bazında refresh kilitleri. Aynı oturumda aynı anda yalnızca bir refresh çalışmasını sağlar.
    /// Yalnızca tek süreç içinde geçerlidir; birden çok BFF instance'ı için dağıtık kilit gerekir.
    /// </summary>
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Gates = new();

    /// <summary>Access token'ın gerçek süresi dolmadan bu kadar önce yenileme yapılır.</summary>
    private static readonly TimeSpan RefreshLeeway = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Verilen oturum kimliği için token setini cache'e yazar. Kayıt, refresh token'ın son geçerlilik zamanına kadar tutulur.
    /// </summary>
    /// <param name="sid">Oturum kimliği.</param>
    /// <param name="tokens">Saklanacak token seti.</param>
    public async Task SaveAsync(string sid, SessionTokens tokens, CancellationToken ct = default)
    {
        var options = new DistributedCacheEntryOptions
        {
            // Refresh token'ın geçerlilik süresi kadar sakla
            AbsoluteExpiration = tokens.RefreshTokenExpiresAt
        };

        await cache.SetStringAsync(Key(sid), JsonSerializer.Serialize(tokens), options, ct);
    }

    /// <summary>
    /// Oturum kimliğine ait token setini cache'ten okur. Kayıt yoksa (oturum sona ermiş ya da iptal edilmişse) <c>null</c> döner.
    /// Yenileme yapmaz.
    /// </summary>
    /// <param name="sid">Oturum kimliği.</param>
    public async Task<SessionTokens?> GetAsync(string sid, CancellationToken ct = default)
    {
        var json = await cache.GetStringAsync(Key(sid), ct);
        return json is null ? null : JsonSerializer.Deserialize<SessionTokens>(json);
    }

    /// <summary>
    /// Oturum kaydını cache'ten siler. Oturumu sunucu tarafında geçersiz kılar: sonraki isteklerde
    /// <c>CookieAuthConfig</c> cookie'yi reddeder ve kullanıcı oturumu kapatılmış olur.
    /// </summary>
    /// <param name="sid">Silinecek oturum kimliği.</param>
    public Task RemoveAsync(string sid, CancellationToken ct = default) =>
        cache.RemoveAsync(Key(sid), ct);

    /// <summary>
    /// Oturumun geçerli token setini döner. Access token'ın süresinin dolmasına <see cref="RefreshLeeway"/> kadar
    /// (60 sn) yakın veya geçmişse önce <see cref="RefreshAsync"/> ile yeniler. Kayıt yoksa
    /// <see cref="SessionExpiredException"/> fırlatır.
    /// </summary>
    /// <param name="sid">Oturum kimliği.</param>
    /// <param name="ct">İptal belirteci.</param>
    public async Task<SessionTokens> GetValidSessionAsync(string sid, CancellationToken ct)
    {
        var session = await GetAsync(sid, ct) ?? throw new SessionExpiredException();

        return session.AccessTokenExpiresAt - RefreshLeeway > DateTimeOffset.UtcNow
            ? session
            : await RefreshAsync(sid, session.AccessToken, ct);
    }

    /// <summary>
    /// Access token'ı refresh token ile yeniler. Aynı oturumdaki eşzamanlı istekler tek seferde yenileme yapar:
    /// kilidi bekleyen istek, bu sırada token zaten değişmişse (<paramref name="staleAccessToken"/> artık
    /// güncel değilse) yeni refresh yapmadan mevcut token setini döner. Refresh token her yenilemede
    /// değiştiği için iki paralel refresh, sunucunun reuse detection mekanizmasıyla oturumu sonlandırabilir.
    /// Yenileme başarılıysa yeni token seti kaydedilir. Auth API 401 dönerse oturum silinir ve
    /// <see cref="SessionExpiredException"/> fırlatılır. Diğer hatalarda (ör. 503) oturum silinmez ve
    /// <see cref="HttpRequestException"/> fırlatılır.
    /// </summary>
    /// <param name="sid">Oturum kimliği.</param>
    /// <param name="staleAccessToken">Çağıranın bildiği, süresi dolmak üzere olan access token.</param>
    /// <param name="ct">İptal belirteci.</param>
    public async Task<SessionTokens> RefreshAsync(string sid, string staleAccessToken, CancellationToken ct)
    {
        var gate = Gates.GetOrAdd(sid, _ => new SemaphoreSlim(1, 1)); // SemaphoreSlim(1, 1) aynı oturum için yenileme işlemini aynı anda yalnızca bir isteğin çalıştırmasını sağlamak için kullanılıyor. Ancak kilit tek başına yetmiyor. Kodda iki katmanlı bir koruma var
    // Parametreler başlangıç sayısını 1, en fazla sayıyı da 1 yapar. Yani ikili bir kilit gibi davranır. Aynı sid için ilk istek kilidi alır, diğerleri WaitAsync ile sırada bekler.
    await gate.WaitAsync(ct);

        try
        {
            var current = await GetAsync(sid, ct) ?? throw new SessionExpiredException();
            if (current.AccessToken != staleAccessToken) 
              return current; // Kilidi alan istek, cache'ten en güncel kaydı okur. Bekleme sırasında başka bir istek token'ı zaten yenilediyse, yeni bir refresh yapmadan o token setini döner.

      var result = await auth.RefreshAsync(current.RefreshToken, ct);

            if (result.IsSuccess)
            {
                var updated = SessionTokens.FromResponse(result.Value!);
                await SaveAsync(sid, updated, ct);
                return updated;
            }

            if (result.StatusCode == StatusCodes.Status401Unauthorized)
            {
                await RemoveAsync(sid, ct);
                throw new SessionExpiredException();
            }

            // Geçici hata (ör. 503): oturumu silmeyiz
            throw new HttpRequestException($"Token yenileme başarısız oldu (HTTP {result.StatusCode}).");
        }
        finally
        {
            gate.Release();
        }
    }

    private static string Key(string sid) => $"session:{sid}";
}
