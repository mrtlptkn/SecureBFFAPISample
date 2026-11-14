using Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Api.Endpoints;

/// <summary>Yetki tabanlı endpoint örnekleri. Veriler bellekte tutulur (örnek amaçlı).</summary>
public static class ProductEndpoints
{
    private static readonly List<ProductDto> Products =
    [
        new(1, "Kalem", 25m),
        new(2, "Defter", 60m)
    ];

    private static readonly object Gate = new();

    public static void MapProductEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/products").WithTags("Products");

        group.MapGet("/", () =>
            {
                lock (Gate)
                {
                    return Results.Ok(Products.ToList());
                }
            })
            .RequireAuthorization(Permissions.Products.Read);

        group.MapPost("/", (CreateProductRequest request) =>
            {
                if (string.IsNullOrWhiteSpace(request.Name) || request.Price < 0)
                    return Results.BadRequest(new { error = "Ürün adı zorunlu ve fiyat negatif olamaz." });

                lock (Gate)
                {
                    var id = Products.Count == 0 ? 1 : Products.Max(p => p.Id) + 1;
                    var product = new ProductDto(id, request.Name.Trim(), request.Price);
                    Products.Add(product);
                    return Results.Created($"/api/products/{id}", product);
                }
            })
            .RequireAuthorization(Permissions.Products.Write);
    }
}
