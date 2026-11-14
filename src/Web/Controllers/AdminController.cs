using Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Models;
using Web.Services;

namespace Web.Controllers;

[Authorize(Policy = Permissions.Users.Read)]
public sealed class AdminController(ApiClient api) : Controller
{
    public async Task<IActionResult> Users(CancellationToken ct)
    {
        var result = await api.GetUsersAsync(ct);
        var users = result.Value ?? new List<AdminUserDto>();
        return View(new AdminUsersViewModel(users, result.IsSuccess ? null : result.Error));
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = Permissions.Users.Manage)]
    public async Task<IActionResult> AssignRole(Guid id, string role, CancellationToken ct)
    {
        var result = await api.AssignRoleAsync(id, role, ct);
        return Done(result.IsSuccess ? "Rol atandı." : result.Error);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = Permissions.Users.Manage)]
    public async Task<IActionResult> SetDisabled(Guid id, bool disabled, CancellationToken ct)
    {
        var result = await api.SetDisabledAsync(id, disabled, ct);
        return Done(result.IsSuccess ? "Kullanıcı durumu güncellendi." : result.Error);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = Permissions.Users.Manage)]
    public async Task<IActionResult> ForceLogout(Guid id, CancellationToken ct)
    {
        var result = await api.ForceLogoutAsync(id, ct);
        return Done(result.IsSuccess ? "Kullanıcının tüm oturumları kapatıldı." : result.Error);
    }

    private IActionResult Done(string? message)
    {
        TempData["Message"] = message;
        return RedirectToAction(nameof(Users));
    }
}
