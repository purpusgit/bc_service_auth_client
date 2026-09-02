/**
 * A bounded cache with a per-entry lifetime and an injectable clock.
 *
 * Written rather than taken from `lru-cache` for one reason that matters: lru-cache
 * captures its time source at module load, so a fake clock installed afterwards has no
 * effect and expiry cannot be driven deterministically in a test. The first version of
 * this package used it, and the conformance test for "never serve an expired entry"
 * PASSED WITHOUT TESTING ANYTHING -- it constructed a second client whose cache was cold,
 * so it would have returned the same result with expiry entirely broken.
 *
 * Expiry is the 60-second revocation reach. A test that cannot fail is not a guard on it.
 *
 * It also drops a runtime dependency from a package thirteen services will install.
 *
 * Semantics, deliberately narrow:
 *   - an entry past its expiry is INVISIBLE and deleted on read; there is no stale mode,
 *     because serving one entry past 60 seconds silently extends the revocation reach
 *   - a read refreshes recency but NOT the expiry -- a credential cannot be kept alive
 *     forever by being used, which is what makes the 60s a ceiling rather than an idle timeout
 *   - at capacity the least recently used entry is evicted (Map preserves insertion order)
 */
export class TtlCache<V> {
  private readonly entries = new Map<string, { value: V; expiresAt: number }>();

  constructor(
    private readonly max: number,
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;

    if (this.now() >= entry.expiresAt) {
      this.entries.delete(key);
      return undefined;
    }

    // Refresh recency only. expiresAt is untouched on purpose.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, value: V): void {
    if (this.entries.has(key)) this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: this.now() + this.ttlMs });

    while (this.entries.size > this.max) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  delete(key: string): void {
    this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }

  /** Present for tests and diagnostics. Counts entries including any not yet reaped. */
  get size(): number {
    return this.entries.size;
  }
}
