using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace Web.Services;

public sealed record ApiResult<T>(bool IsSuccess, int StatusCode, T? Value, string? Error);

public static class ApiErrors
{
    public static async Task<ApiResult<T>> FromResponseAsync<T>(HttpResponseMessage response, CancellationToken ct)
    {
        string? title = null;

        try
        {
            var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>(ct);
            title = problem?.Title;
        }
        catch (JsonException)
        {
            // Gövde problem+json değilse varsayılan mesaj kullanılır
        }
        catch (NotSupportedException)
        {
        }

        return new ApiResult<T>(false, (int)response.StatusCode, default, title ?? "İşlem tamamlanamadı.");
    }
}
