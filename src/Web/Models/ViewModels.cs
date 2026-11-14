using System.ComponentModel.DataAnnotations;
using Contracts;

namespace Web.Models;

public sealed class LoginForm
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}

public sealed class RegisterForm
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required, MinLength(8)]
    public string Password { get; set; } = string.Empty;
}

public sealed record DashboardViewModel(
    string Email,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<ProductDto> Products,
    string? Error);

public sealed record AdminUsersViewModel(
    IReadOnlyList<AdminUserDto> Users,
    string? Error);
