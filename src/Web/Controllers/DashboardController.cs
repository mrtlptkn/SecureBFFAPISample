using Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Web.Models;
using Web.Services;

namespace Web.Controllers;

[Authorize]
public sealed class DashboardController(ApiClient api) : Controller
{
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var permissions = User.FindAll(Permissions.ClaimType).Select(c => c.Value).ToList();

        IReadOnlyList<ProductDto> products = [];
        string? error = null;

        if (permissions.Contains(Permissions.Products.Read))
        {
            var result = await api.GetProductsAsync(ct);
            if (result.IsSuccess)
                products = result.Value ?? new List<ProductDto>();
            else
                error = result.Error;
        }

        var model = new DashboardViewModel(User.Identity?.Name ?? string.Empty, permissions, products, error);
        return View(model);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = Permissions.Products.Write)]
    public async Task<IActionResult> CreateProduct(string name, decimal price, CancellationToken ct)
    {
        var result = await api.CreateProductAsync(new CreateProductRequest(name, price), ct);
        TempData["Message"] = result.IsSuccess ? "Ürün eklendi." : result.Error;
        return RedirectToAction(nameof(Index));
    }
}
