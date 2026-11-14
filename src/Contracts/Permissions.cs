namespace Contracts;

/// <summary>
/// API ve BFF'in ortak kullandığı izin sabitleri.
/// İzinler Identity'de rol ve kullanıcı claim'i olarak saklanır (ClaimType = "permission").
/// </summary>
public static class Permissions
{
    public const string ClaimType = "permission";
    public const string SecurityStampClaimType = "security_stamp";

    public static class Products
    {
        public const string Read = "products.read";
        public const string Write = "products.write";
    }

    public static class Users
    {
        public const string Read = "users.read";
        public const string Manage = "users.manage";
    }

    public static class Roles
    {
        public const string Manage = "roles.manage";
    }

    public static IReadOnlyList<string> All { get; } =
    [
        Products.Read,
        Products.Write,
        Users.Read,
        Users.Manage,
        Roles.Manage
    ];
}
