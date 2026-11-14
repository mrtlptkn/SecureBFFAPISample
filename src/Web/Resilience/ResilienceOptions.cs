namespace Web.Resilience;

public sealed class ResilienceOptions
{
    public const string SectionName = "Resilience";

    /// <summary>Yalnızca GET (idempotent) isteklerde kullanılır.</summary>
    public int MaxRetryAttempts { get; init; } = 2;

    public int RetryDelayMs { get; init; } = 300;

    /// <summary>Her deneme için zaman aşımı.</summary>
    public int AttemptTimeoutSeconds { get; init; } = 10;

    /// <summary>Hata oranı bu eşiği geçerse devre açılır.</summary>
    public double CircuitFailureRatio { get; init; } = 0.5;

    /// <summary>Devrenin değerlendirilmesi için gereken minimum istek sayısı.</summary>
    public int CircuitMinimumThroughput { get; init; } = 10;

    public int CircuitSamplingSeconds { get; init; } = 30;

    /// <summary>Devre açık kaldığı süre; bu sürede istekler API'ye gitmez.</summary>
    public int CircuitBreakSeconds { get; init; } = 30;
}
