using Microsoft.AspNetCore.Identity;

namespace Api.Identity;

public sealed class ApplicationUser : IdentityUser<Guid>
{
    /// <summary>Kullanıcı devre dışıysa hiçbir token geçerli sayılmaz.</summary>
    public bool IsDisabled { get; set; }
}
