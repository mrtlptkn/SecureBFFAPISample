# JwtBffSample

.NET 10 üzerinde, **MVC BFF** (Backend for Frontend) mimarisiyle JWT tabanlı kimlik doğrulama örneği.

- **API** (`src/Api`): Minimal API, ASP.NET Core Identity + EF Core (SQLite), JWT access/refresh token, izin tabanlı yetkilendirme, rate limiting.
- **Web** (`src/Web`): MVC BFF. Token'lar sunucuda saklanır, tarayıcıya yalnızca HttpOnly cookie gider. Tailwind CSS. Polly ile retry, circuit breaker ve timeout.
- **Contracts** (`src/Contracts`): API ve BFF'in ortak DTO'ları ve izin sabitleri.

## Mimari

```
Tarayıcı ──(HttpOnly cookie: __Host-bff)──> Web (BFF) ──(Bearer JWT)──> Api
                                             │
                                             └─ token'lar: sunucu tarafı session store
```

## Güvenlik özeti

| Konu | Uygulama |
|---|---|
| Token tarayıcıda | Hayır. Yalnızca opak session id cookie'de. |
| Access token | 15 dk, HS256, `permission` ve `security_stamp` claim'leri içerir. |
| Refresh token | 7 gün. DB'de yalnızca SHA-256 hash'i saklanır. Her kullanımda rotate edilir. |
| Reuse detection | İptal edilmiş refresh token tekrar kullanılırsa tüm token ailesi iptal edilir. |
| Anında iptal | Her API isteğinde security stamp kontrolü yapılır. Kullanıcı devre dışıysa token reddedilir. |
| Yetki değişikliği | Yumuşak iptal: stamp değişir, refresh token korunur. BFF yeni izinleri refresh ile alır. |
| Devre dışı / zorla çıkış | Sert iptal: stamp değişir ve tüm refresh token'lar iptal edilir. |
| Brute force | IP bazlı rate limit (API ve BFF), e-posta bazlı rate limit (API), Identity lockout (5 denemede 15 dk). |
| Retry | Yalnızca GET isteklerinde. Login, refresh ve yazma isteklerinde retry yok. |
| Cookie | HttpOnly, Secure, SameSite=Strict, `__Host-` öneki, 8 saat, kaydırmasız. |

## Kurulum

### 1. Gereksinimler
- .NET 10 SDK
- Node.js 20+ (Tailwind için)
- `dotnet-ef` aracı: `dotnet tool install --global dotnet-ef`

### 2. API gizli ayarları

```bash
cd src/Api
dotnet user-secrets init
dotnet user-secrets set "Jwt:Key" "BURAYA-EN-AZ-32-KARAKTERLIK-GIZLI-ANAHTAR-YAZIN"
dotnet user-secrets set "Seed:AdminPassword" "Admin!23456"
```

`Admin!23456` değeri `http-client.env.json` içindeki admin şifresiyle aynıdır. Farklı bir şifre kullanırsanız env dosyasını da güncelleyin.

### 3. Migration oluşturma (ilk kez)

Proje kökünde:

```bash
dotnet ef migrations add InitialCreate --project src/Api --startup-project src/Api --output-dir Data/Migrations
```

Migration, uygulama başlarken otomatik uygulanır (`MigrateAsync`). Veritabanı dosyası `src/Api/App_Data/app.db` yoludur.

### 4. API'yi çalıştırma

```bash
dotnet run --project src/Api
```

Adres: `http://localhost:5100`

### 5. Web (BFF) için Tailwind

```bash
cd src/Web
npm install
npm run build:css
```

Geliştirme sırasında CSS'i izlemek için `npm run watch:css` komutunu ayrı bir terminalde çalıştırın. `node_modules` klasörü varsa `dotnet build` de CSS'i otomatik üretir.

### 6. Web'i çalıştırma

```bash
dotnet run --project src/Web
```

Adres: `http://localhost:5200`

## Test

`src/Api/Api.http` dosyasını VS Code (REST Client), Rider veya Visual Studio'da açın. `http-client.env.json` içindeki `dev` ortamını seçin. İstekleri yukarıdan aşağıya sırayla çalıştırın. Her adımın beklenen sonucu dosyada yazılıdır.

## Bilinen sınırlar (örnek kapsamı)

- **E-posta doğrulama yok.** Kayıt sırasında `EmailConfirmed = true` atanır.
- **Tek instance varsayımı.** Refresh kilidi (`SemaphoreSlim`) ve rate limit sayaçları bellekte tutulur. Birden çok instance için Redis tabanlı dağıtık kilit ve sayaç gerekir.
- **Dağıtık cache yok.** `IDistributedCache` bellek tabanlıdır. Üretimde Redis kullanın.
- **Kayan oturum süresi.** Her refresh'te refresh token'ın süresi yenilenir. Mutlak bir üst sınır istiyorsanız `RefreshToken` kaydına oluşturma tarihine dayalı bir sınır ekleyin.
- **Yönetim arayüzü sınırlı.** BFF'te yalnızca kullanıcı listesi, rol atama, devre dışı bırakma ve oturum kapatma ekranı var. Rol izinlerini düzenleme (`PUT /api/admin/roles/{role}/permissions`) ve rol kaldırma için API endpoint'leri hazır, ekranı yok.
- **Zaman sabitliği.** Var olmayan bir e-posta ile var olan bir e-posta için yanıt süreleri birebir eşit değildir. Üretimde bu fark ölçülebilir olabilir.
- **Derleme doğrulaması yapılmadı.** Kod bu ortamda derlenip çalıştırılmadı. Derleme hatası alırsanız paket sürümlerini (`10.0.0`) ve API adlarını kontrol edin.
