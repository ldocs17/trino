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
import io.trino.filesystem.memory.MemoryFileSystemFactory;
import io.trino.plugin.iceberg.DefaultIcebergFileSystemFactory;
import io.trino.plugin.iceberg.IcebergConfig;
import io.trino.plugin.iceberg.catalog.rest.IcebergRestCatalogConfig.Security;
import io.trino.spi.NodeVersion;
import io.trino.spi.catalog.CatalogName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.trino.plugin.iceberg.IcebergTestUtils.FILE_IO_FACTORY;
import static io.trino.type.InternalTypeManager.TESTING_TYPE_MANAGER;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestIcebergRestCatalogPassthroughNameMatchingValidation
{
    @Test
    public void testPassthroughWithCaseInsensitiveNameMatchingRejected()
    {
        assertThatThrownBy(() -> createFactory(Security.OAUTH2, true, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("iceberg.rest-catalog.oauth2.passthrough-enabled")
                .hasMessageContaining("iceberg.rest-catalog.case-insensitive-name-matching");
    }

    @Test
    public void testPassthroughAloneStartsNormally()
    {
        assertThatCode(() -> createFactory(Security.OAUTH2, true, false)).doesNotThrowAnyException();
    }

    @Test
    public void testCaseInsensitiveNameMatchingAloneStartsNormally()
    {
        assertThatCode(() -> createFactory(Security.OAUTH2, false, true)).doesNotThrowAnyException();
    }

    @Test
    public void testCheckActiveOnlyForOAuth2()
    {
        // The same flag combination is harmless when security is not OAuth2, since passthrough is an OAuth2-only feature.
        assertThatCode(() -> createFactory(Security.NONE, true, true)).doesNotThrowAnyException();
    }

    private static TrinoIcebergRestCatalogFactory createFactory(Security security, boolean passthroughEnabled, boolean caseInsensitiveNameMatching)
    {
        IcebergRestCatalogConfig restConfig = new IcebergRestCatalogConfig()
                .setBaseUri("http://localhost:8080")
                .setSecurity(security)
                .setCaseInsensitiveNameMatching(caseInsensitiveNameMatching);
        SecurityProperties securityProperties = new SecurityProperties()
        {
            @Override
            public Map<String, String> get()
            {
                return ImmutableMap.of();
            }

            @Override
            public boolean tokenPassthroughEnabled()
            {
                return passthroughEnabled;
            }
        };
        NodeVersion nodeVersion = new NodeVersion("test");
        return new TrinoIcebergRestCatalogFactory(
                new DefaultIcebergFileSystemFactory(new MemoryFileSystemFactory()),
                FILE_IO_FACTORY,
                new CatalogName("iceberg_rest"),
                restConfig,
                securityProperties,
                new IcebergRestCatalogPropertiesProvider(restConfig, securityProperties, nodeVersion),
                new IcebergConfig(),
                TESTING_TYPE_MANAGER,
                nodeVersion);
    }
}
