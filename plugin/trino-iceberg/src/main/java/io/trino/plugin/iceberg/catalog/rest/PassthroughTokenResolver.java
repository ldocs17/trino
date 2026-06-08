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

import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Resolves the per-user OAuth2 bearer token that Trino forwards to the Iceberg REST
 * catalog. The token is supplied by the client as the {@value #EXTRA_CREDENTIAL_TOKEN_KEY}
 * extra credential. When passthrough is disabled, or when no usable token is present,
 * the resolver yields {@link Optional#empty()} so callers fall back to the catalog's
 * statically configured authentication.
 */
public final class PassthroughTokenResolver
{
    public static final String EXTRA_CREDENTIAL_TOKEN_KEY = "iceberg.oauth2.token";

    private final boolean enabled;

    public PassthroughTokenResolver(boolean enabled)
    {
        this.enabled = enabled;
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
        return Optional.of(token);
    }
}
