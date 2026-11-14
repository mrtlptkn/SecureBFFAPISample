namespace Contracts;

public sealed record ProductDto(int Id, string Name, decimal Price);

public sealed record CreateProductRequest(string Name, decimal Price);
