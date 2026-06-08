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
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.EXTRA_CREDENTIAL_TOKEN_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestPassthroughTokenResolver
{
    private static final PassthroughTokenResolver ENABLED = new PassthroughTokenResolver(true);
    private static final PassthroughTokenResolver DISABLED = new PassthroughTokenResolver(false);

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
}
