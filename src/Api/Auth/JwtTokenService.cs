using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.Identity;
using Contracts;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Api.Auth;

public sealed class JwtTokenService(IOptions<JwtOptions> options, ILogger<JwtTokenService> logger)
{
    private readonly JwtOptions _options = options.Value;

    private readonly SigningCredentials _credentials = new(
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.Key)),
        SecurityAlgorithms.HmacSha256);

    public (string Token, DateTimeOffset ExpiresAt) CreateAccessToken(
        ApplicationUser user,
        IReadOnlyList<string> permissions)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(_options.AccessTokenMinutes);

        var jti = Guid.NewGuid().ToString();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, jti),
            // Security stamp: kullanıcının yetkisi/durumu değişince bu değer eşleşmez ve token reddedilir
            new(Permissions.SecurityStampClaimType, user.SecurityStamp ?? string.Empty)
        };

        claims.AddRange(permissions.Select(p => new Claim(Permissions.ClaimType, p)));

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: _credentials);

        var encoded = new JwtSecurityTokenHandler().WriteToken(token);

        // TODO: Yalnızca test amaçlı! Access token maskelenmeden loglanıyor. Test bitince AccessToken alanını kaldırın.
        logger.LogInformation(
            "Access token issued. UserId={UserId} Jti={Jti} ExpiresAt={ExpiresAt} PermissionCount={PermissionCount} AccessToken={AccessToken}",
            user.Id, jti, expires, permissions.Count, encoded);

        return (encoded, expires);
    }
}
