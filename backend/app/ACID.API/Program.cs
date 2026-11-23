using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// All ACID contracts (contracts/v1) use snake_case field names.
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
});

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new HealthResponse(
        Status: "ok",
        Service: ServiceInfo.Name,
        Version: ServiceInfo.Version,
        Timestamp: DateTime.UtcNow)))
    .WithName("GetHealth");

app.Run();

internal static class ServiceInfo
{
    public const string Name = "acid-backend";
    public const string Version = "0.1.0";
}

internal sealed record HealthResponse(string Status, string Service, string Version, DateTime Timestamp);

// Exposes Program to the integration-test project (WebApplicationFactory<Program>).
public partial class Program;