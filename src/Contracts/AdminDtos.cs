namespace Contracts;

public sealed record AdminUserDto(
    string Id,
    string Email,
    bool IsDisabled,
    IReadOnlyList<string> Roles);

public sealed record AssignRoleRequest(string Role);

public sealed record RoleDto(string Name, IReadOnlyList<string> Permissions);

public sealed record UpdateRolePermissionsRequest(IReadOnlyList<string> Permissions);
