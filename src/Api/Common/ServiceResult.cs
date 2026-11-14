using Microsoft.AspNetCore.Http;

namespace Api.Common;

/// <summary>Servis katmanından HTTP katmanına taşınan basit sonuç tipi.</summary>
public sealed record ServiceResult<T>(T? Value, int StatusCode, string? Error)
{
    public bool IsSuccess => Error is null;

    public static ServiceResult<T> Ok(T value) => new(value, StatusCodes.Status200OK, null);

    public static ServiceResult<T> Fail(int statusCode, string error) => new(default, statusCode, error);

    public IResult ToHttpResult() =>
        IsSuccess
            ? Results.Ok(Value)
            : Results.Problem(title: Error, statusCode: StatusCode);
}
