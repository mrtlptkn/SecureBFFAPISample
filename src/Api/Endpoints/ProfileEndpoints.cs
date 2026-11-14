using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Api.Endpoints;

public static class ProfileEndpoints
{
    /// <summary>Yalnızca oturum açmış olmak yeterli; izin gerektirmez.</summary>
    public static void MapProfileEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/profile", (ClaimsPrincipal user) => Results.Ok(new
            {
                userId = user.FindFirst("sub")?.Value,
                email = user.FindFirst("email")?.Value
            }))
            .RequireAuthorization()
            .WithTags("Profile");
    }
}
