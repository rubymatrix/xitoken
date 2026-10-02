namespace XiToken;

/// <summary>Remembers consumed token ids until they expire. Worlds with several processes need a shared implementation (e.g. a DB table keyed on issuer + jti).</summary>
public interface IReplayGuard
{
    /// <summary>Records <paramref name="tokenId"/> and returns true, or returns false if it was already recorded.</summary>
    bool TryConsume(string issuer, string tokenId, DateTimeOffset keepUntil);
}

public sealed class MemoryReplayGuard(TimeProvider? clock = null) : IReplayGuard
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Dictionary<(string, string), DateTimeOffset> _seen = [];
    private readonly object _lock = new();

    public bool TryConsume(string issuer, string tokenId, DateTimeOffset keepUntil)
    {
        lock (_lock)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            if (_seen.Count > 1024)
            {
                foreach (var stale in _seen.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList())
                    _seen.Remove(stale);
            }
            if (_seen.TryGetValue((issuer, tokenId), out DateTimeOffset until) && until > now)
                return false;
            _seen[(issuer, tokenId)] = keepUntil;
            return true;
        }
    }
}
