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
import io.airlift.http.server.HttpServerConfig;
import io.airlift.http.server.HttpServerInfo;
import io.airlift.http.server.ServerFeature;
import io.airlift.http.server.testing.TestingHttpServer;
import io.airlift.node.NodeInfo;
import io.trino.cache.EvictableCacheBuilder;
import io.trino.filesystem.memory.MemoryFileSystemFactory;
import io.trino.plugin.iceberg.DefaultIcebergFileSystemFactory;
import io.trino.plugin.iceberg.catalog.TrinoCatalog;
import io.trino.plugin.iceberg.catalog.rest.IcebergRestCatalogConfig.Security;
import io.trino.spi.catalog.CatalogName;
import io.trino.spi.connector.ConnectorSession;
import io.trino.spi.security.ConnectorIdentity;
import io.trino.testing.TestingConnectorSession;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.rest.RESTCatalogAdapter;
import org.apache.iceberg.rest.RESTCatalogServlet;
import org.apache.iceberg.rest.RESTSessionCatalog;
import org.apache.iceberg.rest.auth.AuthProperties;
import org.apache.iceberg.rest.auth.OAuth2Properties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static io.trino.plugin.iceberg.catalog.rest.IcebergRestCatalogConfig.SessionType.USER;
import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.EXTRA_CREDENTIAL_TOKEN_KEY;
import static io.trino.plugin.iceberg.catalog.rest.RestCatalogTestUtils.backendCatalog;
import static io.trino.type.InternalTypeManager.TESTING_TYPE_MANAGER;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestIcebergRestCatalogTokenPassthrough
{
    private final List<String> capturedAuthorizationHeaders = new CopyOnWriteArrayList<>();
    private final List<String> capturedRequestLines = new CopyOnWriteArrayList<>();

    private Catalog backend;
    private TestingHttpServer testServer;
    private RESTSessionCatalog restSessionCatalog;
    private TrinoCatalog catalog;

    @BeforeAll
    public void setUp()
            throws Exception
    {
        Path warehouseLocation = Files.createTempDirectory(null);
        backend = backendCatalog(warehouseLocation);

        RESTCatalogAdapter adapter = new RESTCatalogAdapter(backend);
        RecordingRestCatalogServlet servlet = new RecordingRestCatalogServlet(adapter);

        NodeInfo nodeInfo = new NodeInfo("test");
        HttpServerConfig config = new HttpServerConfig()
                .setHttpPort(0)
                .setHttpEnabled(true);
        HttpServerInfo httpServerInfo = new HttpServerInfo(config, nodeInfo);
        testServer = new TestingHttpServer("rest-catalog", httpServerInfo, nodeInfo, config, servlet, ServerFeature.builder()
                .withLegacyUriCompliance(true)
                .build());
        testServer.start();

        restSessionCatalog = new RESTSessionCatalog();
        restSessionCatalog.initialize("iceberg_rest", ImmutableMap.<String, String>builder()
                .put(CatalogProperties.URI, testServer.getBaseUrl().toString())
                .put(AuthProperties.AUTH_TYPE, AuthProperties.AUTH_TYPE_OAUTH2)
                .put(OAuth2Properties.TOKEN, "static-bootstrap-token")
                .put(OAuth2Properties.TOKEN_REFRESH_ENABLED, "false")
                .buildOrThrow());

        catalog = new TrinoRestCatalog(
                new DefaultIcebergFileSystemFactory(new MemoryFileSystemFactory()),
                restSessionCatalog,
                new CatalogName("iceberg_rest"),
                Security.OAUTH2,
                USER,
                ImmutableMap.of(),
                false,
                "test",
                TESTING_TYPE_MANAGER,
                false,
                false,
                EvictableCacheBuilder.newBuilder().expireAfterWrite(1000, MILLISECONDS).shareNothingWhenDisabled().build(),
                EvictableCacheBuilder.newBuilder().expireAfterWrite(1000, MILLISECONDS).shareNothingWhenDisabled().build(),
                true,
                true);
    }

    @AfterAll
    public void tearDown()
            throws Exception
    {
        if (restSessionCatalog != null) {
            restSessionCatalog.close();
        }
        if (testServer != null) {
            testServer.stop();
        }
        if (backend instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    @Test
    public void testUserTokenForwardedAsBearer()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        catalog.listNamespaces(sessionForUser("alice", "user-token-alice"));

        assertThat(capturedAuthorizationHeaders)
                .contains("Bearer user-token-alice");
        // Every request in this window is user-scoped, so the static catalog bootstrap token must not appear
        assertThat(capturedAuthorizationHeaders)
                .doesNotContain("Bearer static-bootstrap-token");
        // The bearer is forwarded as-is: no token exchange round trip occurs
        assertThat(capturedRequestLines)
                .noneMatch(line -> line.contains("oauth/tokens") || line.contains("v1/oauth"));
    }

    @Test
    public void testDistinctUsersForwardDistinctBearers()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        catalog.listNamespaces(sessionForUser("alice", "user-token-alice"));
        catalog.listNamespaces(sessionForUser("bob", "user-token-bob"));

        assertThat(capturedAuthorizationHeaders).contains("Bearer user-token-alice");
        assertThat(capturedAuthorizationHeaders).contains("Bearer user-token-bob");
    }

    private static ConnectorSession sessionForUser(String user, String token)
    {
        return TestingConnectorSession.builder()
                .setIdentity(ConnectorIdentity.forUser(user)
                        .withExtraCredentials(ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token))
                        .build())
                .build();
    }

    private class RecordingRestCatalogServlet
            extends RESTCatalogServlet
    {
        public RecordingRestCatalogServlet(RESTCatalogAdapter adapter)
        {
            super(adapter);
        }

        @Override
        protected void service(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException
        {
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                capturedAuthorizationHeaders.add(authorization);
            }
            capturedRequestLines.add(request.getMethod() + " " + request.getRequestURI());
            super.service(request, response);
        }
    }
}
