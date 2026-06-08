/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.iceberg.catalog.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.trino.spi.TrinoException;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static io.trino.plugin.iceberg.IcebergErrorCode.ICEBERG_OAUTH2_TOKEN_EXPIRED;
import static java.util.Objects.requireNonNull;

/**
 * Resolves the per-user OAuth2 bearer token that Trino forwards to the Iceberg REST
 * catalog. The token is supplied by the client as the {@value #EXTRA_CREDENTIAL_TOKEN_KEY}
 * extra credential. When passthrough is disabled, or when no usable token is present,
 * the resolver yields {@link Optional#empty()} so callers fall back to the catalog's
 * statically configured authentication.
 *
 * <p>As a best-effort error-quality aid, the resolver performs a signature-free parse of
 * a JWT token's {@code exp} claim and fails fast when the token is already expired or about
 * to expire, so the user gets an actionable message instead of a cryptic downstream auth
 * failure. This is a staleness hint only — <b>not</b> an authorization control — and opaque
 * (non-JWT) tokens skip the check and pass through unchanged. The parse never verifies the
 * signature and never makes a network call.
 */
public final class PassthroughTokenResolver
{
    public static final String EXTRA_CREDENTIAL_TOKEN_KEY = "iceberg.oauth2.token";

    /**
     * Tokens expiring within this window are treated as already stale so that a query does not
     * race the token's expiry on its way to the REST catalog.
     */
    static final Duration EXPIRY_LEEWAY = Duration.ofSeconds(10);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final boolean enabled;
    private final Clock clock;

    public PassthroughTokenResolver(boolean enabled)
    {
        this(enabled, Clock.systemUTC());
    }

    PassthroughTokenResolver(boolean enabled, Clock clock)
    {
        this.enabled = enabled;
        this.clock = requireNonNull(clock, "clock is null");
    }

    public Optional<String> resolveBearerToken(Map<String, String> extraCredentials)
    {
        requireNonNull(extraCredentials, "extraCredentials is null");
        if (!enabled) {
            return Optional.empty();
        }
        String token = extraCredentials.get(EXTRA_CREDENTIAL_TOKEN_KEY);
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        checkNotExpired(token);
        return Optional.of(token);
    }

    private void checkNotExpired(String token)
    {
        Optional<Instant> expiry = parseExpiry(token);
        if (expiry.isEmpty()) {
            return;
        }
        Instant now = clock.instant();
        if (!expiry.get().isAfter(now.plus(EXPIRY_LEEWAY))) {
            throw new TrinoException(
                    ICEBERG_OAUTH2_TOKEN_EXPIRED,
                    "OAuth2 token passed through the '%s' extra credential is expired (exp=%s); obtain a fresh token and retry".formatted(
                            EXTRA_CREDENTIAL_TOKEN_KEY, expiry.get()));
        }
    }

    /**
     * Best-effort, signature-free extraction of the JWT {@code exp} claim. Returns empty for any
     * token that is not a parseable JWT carrying a numeric {@code exp}, so opaque tokens pass through.
     */
    private static Optional<Instant> parseExpiry(String token)
    {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            JsonNode payload = OBJECT_MAPPER.readTree(URL_DECODER.decode(parts[1]));
            JsonNode exp = payload.get("exp");
            if (exp == null || !exp.isNumber()) {
                return Optional.empty();
            }
            return Optional.of(Instant.ofEpochSecond(exp.asLong()));
        }
        catch (IOException | RuntimeException _) {
            // not a JWT we can read — treat as opaque and pass through
            return Optional.empty();
        }
    }
}
