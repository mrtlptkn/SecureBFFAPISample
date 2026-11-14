using Microsoft.Extensions.Http.Resilience;
using Polly;

namespace Web.Resilience;

public static class ResiliencePolicies
{
    /// <summary>
    /// Yalnızca GET istekleri gönderen istemci için. Retry, idempotent olmayan isteklere
    /// uygulanmaz; bu yüzden yazma ve kimlik işlemleri ayrı bir pipeline kullanır.
    /// </summary>
    public static void ConfigureReadPipeline(
        ResiliencePipelineBuilder<HttpResponseMessage> pipeline,
        ResilienceOptions options)
    {
        pipeline.AddRetry(new HttpRetryStrategyOptions
        {
            MaxRetryAttempts = options.MaxRetryAttempts,
            BackoffType = DelayBackoffType.Exponential,
            UseJitter = true,
            Delay = TimeSpan.FromMilliseconds(options.RetryDelayMs)
        });

        ConfigureCommon(pipeline, options);
    }

    /// <summary>
    /// Yazma (POST/PUT/DELETE) ve login/refresh için. Retry yok: yanıt kaybolup tekrar gönderilirse
    /// refresh token reuse detection oturumu sonlandırabilir. Yalnızca circuit breaker ve timeout uygulanır.
    /// </summary>
    public static void ConfigureNoRetryPipeline(
        ResiliencePipelineBuilder<HttpResponseMessage> pipeline,
        ResilienceOptions options) =>
        ConfigureCommon(pipeline, options);

    private static void ConfigureCommon(
        ResiliencePipelineBuilder<HttpResponseMessage> pipeline,
        ResilienceOptions options)
    {
        pipeline.AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
        {
            FailureRatio = options.CircuitFailureRatio,
            MinimumThroughput = options.CircuitMinimumThroughput,
            SamplingDuration = TimeSpan.FromSeconds(options.CircuitSamplingSeconds),
            BreakDuration = TimeSpan.FromSeconds(options.CircuitBreakSeconds)
        });

        pipeline.AddTimeout(TimeSpan.FromSeconds(options.AttemptTimeoutSeconds));
    }
}
