using System.Security.Claims;
using Api.Common;
using Api.Data.Seeding;
using Api.Identity;
using Contracts;
using Microsoft.AspNetCore.Identity;

namespace Api.Auth;

/// <summary>
/// Kullanıcı kaydı, giriş, token yenileme, çıkış ve oturumdaki kullanıcı bilgisini
/// (<c>/me</c>) yöneten kimlik doğrulama servisi. Parola doğrulaması ve kilitleme
/// için ASP.NET Core Identity'yi, erişim ve yenileme token'ları için
/// <see cref="JwtTokenService"/> ve <see cref="RefreshTokenService"/> servislerini kullanır.
/// </summary>
public sealed class AuthService(
    UserManager<ApplicationUser> users,
    PermissionService permissions,
    JwtTokenService jwt,
    RefreshTokenService refreshTokens,
    ILogger<AuthService> logger)
{
  private const string GenericLoginError = "E-posta veya şifre hatalı.";
  private const string GenericSessionError = "Oturum geçersiz. Lütfen tekrar giriş yapın.";

  /// <summary>
  /// Yeni bir kullanıcı oluşturur, <see cref="IdentitySeeder.UserRole"/> rolünü atar
  /// ve kullanıcının profil bilgilerini döner. E-posta doğrulaması bu örnekte kapsam dışıdır.
  /// </summary>
  /// <param name="request">E-posta ve parola içeren kayıt isteği.</param>
  /// <param name="ct">İptal belirteci.</param>
  /// <returns>
  /// Başarılıysa oluşturulan kullanıcının bilgileri; aksi halde 400 durum kodlu hata.
  /// Yinelenen e-posta hataları gizlenir (user enumeration koruması).
  /// </returns>
  public async Task<ServiceResult<MeResponse>> RegisterAsync(RegisterRequest request, CancellationToken ct)
  {
    var user = new ApplicationUser
    {
      UserName = request.Email,
      Email = request.Email,
      // E-posta doğrulama bu örnekte kapsam dışı
      EmailConfirmed = true
    };

    var result = await users.CreateAsync(user, request.Password);
    if (!result.Succeeded)
    {
      // Kayıtlı e-posta bilgisi sızdırılmaz (user enumeration). Yalnızca şifre kuralı hataları gösterilir.
      // Duplicate hata mesajlarını temizleriz -> 
      // "bu e-posta kayıtlı" bilgisi sızmaz. Filtrede hiç mesaj kalmazsa, yani yalnızca duplicate hatası varsa, genel mesaj döner: "Kayıt tamamlanamadı. Bilgilerinizi kontrol edin.
      var messages = result.Errors
          .Where(e => !e.Code.StartsWith("Duplicate", StringComparison.Ordinal))
          .Select(e => e.Description)
          .ToList();

      var message = messages.Count > 0
          ? string.Join(" ", messages)
          : "Kayıt tamamlanamadı. Bilgilerinizi kontrol edin.";

      return ServiceResult<MeResponse>.Fail(StatusCodes.Status400BadRequest, message);
    }

    await users.AddToRoleAsync(user, IdentitySeeder.UserRole);
    return ServiceResult<MeResponse>.Ok(await BuildMeAsync(user));
  }

  /// <summary>
  /// E-posta ve parola ile kullanıcıyı doğrular ve yeni bir erişim/yenileme token çifti üretir.
  /// Kullanıcı yoksa, devre dışıysa veya kilitliyse ya da parola yanlışsa aynı genel hata
  /// mesajı döner. Yanlış parolada başarısız deneme sayacı artırılır.
  /// </summary>
  /// <param name="request">E-posta ve parola içeren giriş isteği.</param>
  /// <param name="ct">İptal belirteci.</param>
  /// <returns>Başarılıysa token yanıtı; aksi halde 401 durum kodlu hata.</returns>
  public async Task<ServiceResult<TokenResponse>> LoginAsync(LoginRequest request, CancellationToken ct)
  {
    var user = await users.FindByEmailAsync(request.Email);
    if (user is null || user.IsDisabled)
      return ServiceResult<TokenResponse>.Fail(StatusCodes.Status401Unauthorized, GenericLoginError);

    if (await users.IsLockedOutAsync(user))
      return ServiceResult<TokenResponse>.Fail(StatusCodes.Status401Unauthorized, GenericLoginError);

    if (!await users.CheckPasswordAsync(user, request.Password))
    {
      // Identity lockout sayacı: AllowedFailedAttempts aşılınca hesap geçici olarak kilitlenir
      await users.AccessFailedAsync(user);
      return ServiceResult<TokenResponse>.Fail(StatusCodes.Status401Unauthorized, GenericLoginError);
    }

    await users.ResetAccessFailedCountAsync(user);

    var tokens = await IssueTokensAsync(user, familyId: null, ct);
    logger.LogInformation("Login succeeded, new token pair issued. UserId={UserId}", user.Id);
    return ServiceResult<TokenResponse>.Ok(tokens);
  }

  /// <summary>
  /// Geçerli bir yenileme token'ını rotasyonla değiştirerek aynı token ailesi içinde yeni
  /// bir token çifti üretir. Kullanıcı bulunamazsa veya devre dışıysa token ailesi iptal edilir.
  /// İzinler veritabanından yeniden okunur.
  /// </summary>
  /// <param name="request">Yenilenecek yenileme token'ını içeren istek.</param>
  /// <param name="ct">İptal belirteci.</param>
  /// <returns>Başarılıysa yeni token yanıtı; aksi halde 401 durum kodlu hata.</returns>
  public async Task<ServiceResult<TokenResponse>> RefreshAsync(RefreshRequest request, CancellationToken ct)
  {
    // RotateAsync gelen token'ın hash'ini bulur. Bulamazsa 401 döndürür. 
    var rotation = await refreshTokens.RotateAsync(request.RefreshToken, ct);
    if (!rotation.Succeeded)
    {
      logger.LogInformation("Token refresh failed: refresh token is invalid, expired or reused.");
      return ServiceResult<TokenResponse>.Fail(StatusCodes.Status401Unauthorized, GenericSessionError);
    }

    var user = await users.FindByIdAsync(rotation.UserId.ToString());
    if (user is null || user.IsDisabled)
    {
      logger.LogInformation(
        "Token refresh failed: user not found or disabled. UserId={UserId} FamilyId={FamilyId}",
        rotation.UserId, rotation.FamilyId);
      await refreshTokens.RevokeFamilyAsync(rotation.FamilyId, "user-invalid", ct);
      return ServiceResult<TokenResponse>.Fail(StatusCodes.Status401Unauthorized, GenericSessionError);
    }

    // Aynı aileyle yeni refresh token; izinler veritabanından yeniden okunur
    var tokens = await IssueTokensAsync(user, rotation.FamilyId, ct);
    logger.LogInformation(
      "Token refresh succeeded, access and refresh tokens replaced. UserId={UserId} FamilyId={FamilyId}",
      user.Id, rotation.FamilyId);
    return ServiceResult<TokenResponse>.Ok(tokens);
  }

  /// <summary>
  /// Verilen yenileme token'ını iptal ederek kullanıcının oturumunu sonlandırır.
  /// </summary>
  /// <param name="refreshToken">İptal edilecek yenileme token'ı.</param>
  /// <param name="ct">İptal belirteci.</param>
  /// <returns>Tamamlandığında biten bir <see cref="Task"/>.</returns>
  public Task LogoutAsync(string refreshToken, CancellationToken ct) =>
      refreshTokens.RevokeByTokenAsync(refreshToken, ct);

  /// <summary>
  /// Kimliği doğrulanmış kullanıcının <c>sub</c> talebinden kullanıcıyı bulur ve
  /// profil bilgilerini (rol ve izinler dahil) döner.
  /// </summary>
  /// <param name="principal">Erişim token'ından oluşturulmuş kullanıcı kimliği.</param>
  /// <param name="ct">İptal belirteci.</param>
  /// <returns>Kullanıcı bulunursa profil bilgileri; aksi halde 404 durum kodlu hata.</returns>
  public async Task<ServiceResult<MeResponse>> GetMeAsync(ClaimsPrincipal principal, CancellationToken ct)
  {
    var subject = principal.FindFirst("sub")?.Value;
    var user = await users.FindByIdAsync(subject ?? string.Empty);
    if (user is null)
      return ServiceResult<MeResponse>.Fail(StatusCodes.Status404NotFound, "Kullanıcı bulunamadı.");

    return ServiceResult<MeResponse>.Ok(await BuildMeAsync(user));
  }

  /// <summary>
  /// Kullanıcının izinlerini alır, erişim token'ı ve yeni bir yenileme token'ı üretir.
  /// <paramref name="familyId"/> verilirse yenileme token'ı aynı token ailesine eklenir;
  /// verilmezse yeni bir aile başlatılır.
  /// </summary>
  /// <param name="user">Token'ları üretilecek kullanıcı.</param>
  /// <param name="familyId">Mevcut token ailesinin kimliği; yeni oturum için <c>null</c>.</param>
  /// <param name="ct">İptal belirteci.</param>
  /// <returns>Erişim token'ı, yenileme token'ı, süreleri ve izinleri içeren token yanıtı.</returns>
  private async Task<TokenResponse> IssueTokensAsync(ApplicationUser user, Guid? familyId, CancellationToken ct)
  {
    var perms = await permissions.GetPermissionsAsync(user);
    var (accessToken, accessExpires) = jwt.CreateAccessToken(user, perms);
    var refresh = await refreshTokens.IssueAsync(user.Id, familyId, ct);

    return new TokenResponse(
        accessToken,
        accessExpires,
        refresh.Token,
        refresh.ExpiresAt,
        user.Email ?? string.Empty,
        perms);
  }

  /// <summary>
  /// Kullanıcının rollerini ve izinlerini okuyarak <see cref="MeResponse"/> nesnesi oluşturur.
  /// </summary>
  /// <param name="user">Profil bilgisi oluşturulacak kullanıcı.</param>
  /// <returns>Kullanıcı kimliği, e-posta, roller ve izinleri içeren profil yanıtı.</returns>
  private async Task<MeResponse> BuildMeAsync(ApplicationUser user)
  {
    var roles = await users.GetRolesAsync(user);
    var perms = await permissions.GetPermissionsAsync(user);
    return new MeResponse(user.Id.ToString(), user.Email ?? string.Empty, roles.ToList(), perms);
  }
}
