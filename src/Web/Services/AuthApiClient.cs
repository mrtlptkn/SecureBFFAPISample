using System.Net.Http.Json;
using Contracts;

namespace Web.Services;

/// <summary>Kimlik endpoint'leri. Oturum henüz yokken (login/register/refresh) kullanılır; token eklemez.</summary>
public sealed class AuthApiClient(IHttpClientFactory factory)
{
    private HttpClient Client => factory.CreateClient("auth");

    public Task<ApiResult<TokenResponse>> LoginAsync(string email, string password, CancellationToken ct) =>
        PostAsync<TokenResponse>("/api/auth/login", new LoginRequest(email, password), ct);

    public Task<ApiResult<MeResponse>> RegisterAsync(string email, string password, CancellationToken ct) =>
        PostAsync<MeResponse>("/api/auth/register", new RegisterRequest(email, password), ct);

    public Task<ApiResult<TokenResponse>> RefreshAsync(string refreshToken, CancellationToken ct) =>
        PostAsync<TokenResponse>("/api/auth/refresh", new RefreshRequest(refreshToken), ct);

    public async Task LogoutAsync(string refreshToken, CancellationToken ct)
    {
        using var response = await Client.PostAsJsonAsync("/api/auth/logout", new LogoutRequest(refreshToken), ct);
    }

    private async Task<ApiResult<T>> PostAsync<T>(string path, object body, CancellationToken ct)
    {
        using var response = await Client.PostAsJsonAsync(path, body, ct);

        if (!response.IsSuccessStatusCode)
            return await ApiErrors.FromResponseAsync<T>(response, ct);

        var value = await response.Content.ReadFromJsonAsync<T>(ct);
        return new ApiResult<T>(true, (int)response.StatusCode, value, null);
    }
}
