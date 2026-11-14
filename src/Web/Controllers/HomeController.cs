using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[AllowAnonymous]
public sealed class HomeController : Controller
{
    public IActionResult ServiceUnavailable() => View();

    public IActionResult Forbidden() => View();
}
