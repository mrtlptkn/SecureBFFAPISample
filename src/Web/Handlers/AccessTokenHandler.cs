using System.Net;
using System.Net.Http.Headers;
using Web.Auth;

namespace Web.Handlers;

/// <summary>
/// Tarayıcıdan gelen isteğin oturumuna ait access token'ı API çağrısına ekler.
/// Süre dolmak üzereyse önce yeniler. API 401 dönerse bir kez daha yenileyip isteği tekrar gönderir.
/// Bu handler, Polly katmanının DIŞINDA çalışır; 401 yanıtları retry'a girmez.
/// </summary>
public sealed class AccessTokenHandler(ServerTokenStore store, IHttpContextAccessor accessor) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var sid = accessor.HttpContext?.User.FindFirst(SessionClaims.Sid)?.Value
                  ?? throw new SessionExpiredException();

        // Gövdeyi bir kez okuyup tutuyoruz; böylece istek gerektiğinde yeniden kurulabilir
        var body = request.Content is null
            ? null
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);

        var session = await store.GetValidSessionAsync(sid, cancellationToken);

        var response = await base.SendAsync(Clone(request, body, session.AccessToken), cancellationToken);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
            return response;

        response.Dispose();

        var refreshed = await store.RefreshAsync(sid, session.AccessToken, cancellationToken);
        return await base.SendAsync(Clone(request, body, refreshed.AccessToken), cancellationToken);
    }

    private static HttpRequestMessage Clone(HttpRequestMessage original, byte[]? body, string accessToken)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);

        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        if (body is not null && original.Content is not null)
        {
            clone.Content = new ByteArrayContent(body);
            foreach (var header in original.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        clone.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return clone;
    }
}
