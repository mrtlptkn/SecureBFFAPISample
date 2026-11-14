namespace Web.Auth;

/// <summary>Oturum artık geçerli değil. Middleware bunu yakalayıp kullanıcıyı giriş sayfasına yönlendirir.</summary>
public sealed class SessionExpiredException : Exception
{
    public SessionExpiredException()
        : base("Oturum sona erdi.")
    {
    }
}
