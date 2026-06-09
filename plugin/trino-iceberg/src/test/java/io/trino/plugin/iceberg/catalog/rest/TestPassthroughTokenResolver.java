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

import com.google.common.collect.ImmutableMap;
import io.trino.spi.TrinoException;
import org.apache.iceberg.rest.auth.OAuth2Properties;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

import static io.trino.plugin.iceberg.IcebergErrorCode.ICEBERG_OAUTH2_TOKEN_EXPIRED;
import static io.trino.plugin.iceberg.IcebergErrorCode.ICEBERG_OAUTH2_TOKEN_MISSING;
import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.EXPIRY_LEEWAY;
import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.EXTRA_CREDENTIAL_TOKEN_KEY;
import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.MissingTokenBehavior.FALLBACK;
import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.MissingTokenBehavior.REJECT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestPassthroughTokenResolver
{
    private static final Instant NOW = Instant.parse("2026-06-08T00:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PassthroughTokenResolver ENABLED = new PassthroughTokenResolver(true, REJECT, FIXED_CLOCK);
    private static final PassthroughTokenResolver DISABLED = new PassthroughTokenResolver(false, REJECT, FIXED_CLOCK);

    @Test
    public void testEnabledWithTokenReturnsToken()
    {
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "user-token")))
                .contains("user-token");
    }

    @Test
    public void testEnabledWithBlankTokenReturnsEmpty()
    {
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "")))
                .isEmpty();
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "   ")))
                .isEmpty();
    }

    @Test
    public void testEnabledWithoutTokenReturnsEmpty()
    {
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of()))
                .isEmpty();
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of("other.credential", "value")))
                .isEmpty();
    }

    @Test
    public void testRejectBehaviorThrowsOnMissingToken()
    {
        PassthroughTokenResolver resolver = new PassthroughTokenResolver(true, REJECT, FIXED_CLOCK);
        assertThatThrownBy(resolver::checkMissingTokenAllowed)
                .isInstanceOf(TrinoException.class)
                .hasFieldOrPropertyWithValue("errorCode", ICEBERG_OAUTH2_TOKEN_MISSING.toErrorCode())
                .hasMessageContaining(EXTRA_CREDENTIAL_TOKEN_KEY)
                .hasMessageContaining("reconnect");
    }

    @Test
    public void testFallbackBehaviorAllowsMissingToken()
    {
        PassthroughTokenResolver resolver = new PassthroughTokenResolver(true, FALLBACK, FIXED_CLOCK);
        assertThatCode(resolver::checkMissingTokenAllowed).doesNotThrowAnyException();
        assertThat(resolver.missingTokenBehavior()).isEqualTo(FALLBACK);
    }

    @Test
    public void testEnabledReflectsConstruction()
    {
        assertThat(ENABLED.isEnabled()).isTrue();
        assertThat(DISABLED.isEnabled()).isFalse();
    }

    @Test
    public void testDisabledIgnoresToken()
    {
        assertThat(DISABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "user-token")))
                .isEmpty();
    }

    @Test
    public void testDistinctTokensResolveDistinctly()
    {
        Map<String, String> alice = ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "token-alice");
        Map<String, String> bob = ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "token-bob");
        assertThat(ENABLED.resolveBearerToken(alice)).contains("token-alice");
        assertThat(ENABLED.resolveBearerToken(bob)).contains("token-bob");
    }

    @Test
    public void testNullExtraCredentialsRejected()
    {
        assertThatThrownBy(() -> ENABLED.resolveBearerToken(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("extraCredentials is null");
    }

    @Test
    public void testValidJwtPasses()
    {
        String token = jwtExpiringAt(NOW.plusSeconds(3600));
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token)))
                .contains(token);
    }

    @Test
    public void testExpiredJwtRejected()
    {
        String token = jwtExpiringAt(NOW.minusSeconds(60));
        assertThatThrownBy(() -> ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token)))
                .isInstanceOf(TrinoException.class)
                .hasFieldOrPropertyWithValue("errorCode", ICEBERG_OAUTH2_TOKEN_EXPIRED.toErrorCode())
                .hasMessageContaining("expired");
    }

    @Test
    public void testNearExpiryJwtRejected()
    {
        String token = jwtExpiringAt(NOW.plus(EXPIRY_LEEWAY).minusSeconds(1));
        assertThatThrownBy(() -> ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token)))
                .isInstanceOf(TrinoException.class)
                .hasFieldOrPropertyWithValue("errorCode", ICEBERG_OAUTH2_TOKEN_EXPIRED.toErrorCode());
    }

    @Test
    public void testOpaqueTokenSkipsExpiryCheck()
    {
        // not a JWT — no dots, not base64-decodable JSON; must pass through untouched
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "opaque-token")))
                .contains("opaque-token");
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, "not.a.jwt")))
                .contains("not.a.jwt");
    }

    @Test
    public void testJwtWithoutExpClaimPasses()
    {
        String token = jwt("{\"sub\":\"alice\"}");
        assertThat(ENABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token)))
                .contains(token);
    }

    @Test
    public void testDisabledDoesNotCheckExpiry()
    {
        String token = jwtExpiringAt(NOW.minusSeconds(60));
        assertThat(DISABLED.resolveBearerToken(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token)))
                .isEmpty();
    }

    @Test
    public void testStripsLibraryAuthKeys()
    {
        Map<String, String> inbound = ImmutableMap.<String, String>builder()
                .put(EXTRA_CREDENTIAL_TOKEN_KEY, "passthrough")
                .put(OAuth2Properties.TOKEN, "smuggled-bearer")
                .put(OAuth2Properties.CREDENTIAL, "smuggled-credential")
                .put(OAuth2Properties.ACCESS_TOKEN_TYPE, "smuggled-access")
                .put(OAuth2Properties.REFRESH_TOKEN_TYPE, "smuggled-refresh")
                .put(OAuth2Properties.ID_TOKEN_TYPE, "smuggled-id")
                .put(OAuth2Properties.SAML1_TOKEN_TYPE, "smuggled-saml1")
                .put(OAuth2Properties.SAML2_TOKEN_TYPE, "smuggled-saml2")
                .put(OAuth2Properties.JWT_TOKEN_TYPE, "smuggled-jwt")
                .put("benign.credential", "keep-me")
                .buildOrThrow();

        // Every library-recognized auth key and the consumed passthrough key are removed; unrelated
        // extra credentials survive untouched.
        assertThat(ENABLED.stripLibraryAuthCredentials(inbound))
                .containsExactly(Map.entry("benign.credential", "keep-me"));
    }

    @Test
    public void testStripRemovesSmuggledBearerSoQueryIsTokenless()
    {
        // A client placing a bearer under a raw library key (not the passthrough key) is left with no
        // usable token, so REJECT will fail the query rather than honoring the smuggled bearer.
        Map<String, String> smuggled = ImmutableMap.of(OAuth2Properties.TOKEN, "smuggled-bearer");
        assertThat(ENABLED.resolveBearerToken(smuggled)).isEmpty();
        assertThat(ENABLED.stripLibraryAuthCredentials(smuggled)).isEmpty();
    }

    @Test
    public void testStripNullExtraCredentialsRejected()
    {
        assertThatThrownBy(() -> ENABLED.stripLibraryAuthCredentials(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("extraCredentials is null");
    }

    private static String jwtExpiringAt(Instant expiry)
    {
        return jwt("{\"exp\":%d}".formatted(expiry.getEpochSecond()));
    }

    private static String jwt(String payloadJson)
    {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString("{\"alg\":\"none\"}".getBytes(UTF_8));
        String payload = encoder.encodeToString(payloadJson.getBytes(UTF_8));
        return header + "." + payload + ".signature";
    }
}
