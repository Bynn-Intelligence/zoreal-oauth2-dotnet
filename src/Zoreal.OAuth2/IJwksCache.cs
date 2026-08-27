namespace Zoreal.OAuth2;

/// <summary>
/// Where the provider's JWKS JSON is kept between logins. The default is a
/// per-client in-memory store, which is fine for one process and means each
/// process of a multi-process server fetches the JWKS for itself; hand in an
/// adapter over your own cache (IMemoryCache, IDistributedCache, Redis) to
/// share it. The value is one small JSON string under one key, so an adapter
/// is a few lines.
/// </summary>
public interface IJwksCache
{
    /// <summary>The cached value, or null when absent or expired.</summary>
    string? Get(string key);

    /// <summary>Stores the value for at most <paramref name="timeToLive"/>.</summary>
    void Set(string key, string value, TimeSpan timeToLive);

    /// <summary>Drops the value, so the next read refetches.</summary>
    void Remove(string key);
}

/// <summary>
/// The fallback JWKS cache: one process, TTL respected, no eviction beyond
/// overwrite, because it only ever holds the one key set.
/// </summary>
public sealed class InMemoryJwksCache : IJwksCache
{
    private readonly object _gate = new();
    private readonly Dictionary<string, (string Value, DateTimeOffset ExpiresAt)> _store = new();

    public string? Get(string key)
    {
        lock (_gate)
        {
            if (!_store.TryGetValue(key, out var entry)) return null;
            if (entry.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                _store.Remove(key);
                return null;
            }
            return entry.Value;
        }
    }

    public void Set(string key, string value, TimeSpan timeToLive)
    {
        lock (_gate)
        {
            _store[key] = (value, DateTimeOffset.UtcNow.Add(timeToLive));
        }
    }

    public void Remove(string key)
    {
        lock (_gate)
        {
            _store.Remove(key);
        }
    }
}
