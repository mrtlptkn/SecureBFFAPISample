using System.Security.Claims;
using Api.Auth;
using Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Api.Endpoints;

public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin").WithTags("Admin");

        group.MapGet("/users", async (AccountSecurityService security) =>
                Results.Ok(await security.ListUsersAsync()))
            .RequireAuthorization(Permissions.Users.Read);

        group.MapPost("/users/{id:guid}/roles", async (
                Guid id,
                AssignRoleRequest request,
                AccountSecurityService security) =>
            (await security.AssignRoleAsync(id, request.Role)).ToHttpResult())
            .RequireAuthorization(Permissions.Users.Manage);

        group.MapDelete("/users/{id:guid}/roles/{role}", async (
                Guid id,
                string role,
                ClaimsPrincipal actor,
                AccountSecurityService security) =>
            (await security.RemoveRoleAsync(ActorId(actor), id, role)).ToHttpResult())
            .RequireAuthorization(Permissions.Users.Manage);

        group.MapPost("/users/{id:guid}/disable", async (
                Guid id,
                ClaimsPrincipal actor,
                AccountSecurityService security,
                CancellationToken ct) =>
            (await security.SetDisabledAsync(ActorId(actor), id, true, ct)).ToHttpResult())
            .RequireAuthorization(Permissions.Users.Manage);

        group.MapPost("/users/{id:guid}/enable", async (
                Guid id,
                ClaimsPrincipal actor,
                AccountSecurityService security,
                CancellationToken ct) =>
            (await security.SetDisabledAsync(ActorId(actor), id, false, ct)).ToHttpResult())
            .RequireAuthorization(Permissions.Users.Manage);

        group.MapPost("/users/{id:guid}/force-logout", async (
                Guid id,
                AccountSecurityService security,
                CancellationToken ct) =>
            (await security.ForceLogoutAsync(id, ct)).ToHttpResult())
            .RequireAuthorization(Permissions.Users.Manage);

        group.MapGet("/roles", async (AccountSecurityService security) =>
                Results.Ok(await security.ListRolesAsync()))
            .RequireAuthorization(Permissions.Roles.Manage);

        group.MapPut("/roles/{role}/permissions", async (
                string role,
                UpdateRolePermissionsRequest request,
                AccountSecurityService security) =>
            (await security.SetRolePermissionsAsync(role, request.Permissions)).ToHttpResult())
            .RequireAuthorization(Permissions.Roles.Manage);
    }

    private static Guid ActorId(ClaimsPrincipal actor) =>
        Guid.Parse(actor.FindFirst("sub")!.Value);
}
