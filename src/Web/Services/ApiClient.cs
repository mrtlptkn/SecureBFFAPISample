using System.Net.Http.Json;
using Contracts;

namespace Web.Services;

/// <summary>
/// Oturumlu API çağrıları. GET'ler "api-read" (retry dahil), yazmalar "api-write" (retry yok) istemcisinden gider.
/// Her iki istemci de AccessTokenHandler kullanır.
/// </summary>
public sealed class ApiClient(IHttpClientFactory factory)
{
    private HttpClient Read => factory.CreateClient("api-read");
    private HttpClient Write => factory.CreateClient("api-write");

    public Task<ApiResult<MeResponse>> GetMeAsync(CancellationToken ct) =>
        SendAsync<MeResponse>(Read, HttpMethod.Get, "/api/auth/me", null, ct);

    public Task<ApiResult<List<ProductDto>>> GetProductsAsync(CancellationToken ct) =>
        SendAsync<List<ProductDto>>(Read, HttpMethod.Get, "/api/products", null, ct);

    public Task<ApiResult<ProductDto>> CreateProductAsync(CreateProductRequest request, CancellationToken ct) =>
        SendAsync<ProductDto>(Write, HttpMethod.Post, "/api/products", request, ct);

    public Task<ApiResult<List<AdminUserDto>>> GetUsersAsync(CancellationToken ct) =>
        SendAsync<List<AdminUserDto>>(Read, HttpMethod.Get, "/api/admin/users", null, ct);

    public Task<ApiResult<AdminUserDto>> AssignRoleAsync(Guid userId, string role, CancellationToken ct) =>
        SendAsync<AdminUserDto>(Write, HttpMethod.Post, $"/api/admin/users/{userId}/roles", new AssignRoleRequest(role), ct);

    public Task<ApiResult<AdminUserDto>> SetDisabledAsync(Guid userId, bool disabled, CancellationToken ct) =>
        SendAsync<AdminUserDto>(
            Write,
            HttpMethod.Post,
            $"/api/admin/users/{userId}/{(disabled ? "disable" : "enable")}",
            null,
            ct);

    public Task<ApiResult<AdminUserDto>> ForceLogoutAsync(Guid userId, CancellationToken ct) =>
        SendAsync<AdminUserDto>(Write, HttpMethod.Post, $"/api/admin/users/{userId}/force-logout", null, ct);

    private static async Task<ApiResult<T>> SendAsync<T>(
        HttpClient client,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body);

        using var response = await client.SendAsync(request, ct);

        if (!response.IsSuccessStatusCode)
            return await ApiErrors.FromResponseAsync<T>(response, ct);

        var value = await response.Content.ReadFromJsonAsync<T>(ct);
        return new ApiResult<T>(true, (int)response.StatusCode, value, null);
    }
}
