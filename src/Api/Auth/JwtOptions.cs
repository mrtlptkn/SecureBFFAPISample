namespace Api.Auth;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; init; } = "JwtBffSample.Api";
    public string Audience { get; init; } = "JwtBffSample.Web";

    /// <summary>En az 32 karakter. user-secrets ile ayarlanmalı.</summary>
    public string Key { get; init; } = "";

    public int AccessTokenMinutes { get; init; } = 15;
    public int RefreshTokenDays { get; init; } = 7;
}
