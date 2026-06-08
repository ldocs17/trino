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
import io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.MissingTokenBehavior;
import io.trino.spi.TrinoException;
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
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static io.trino.plugin.iceberg.IcebergErrorCode.ICEBERG_OAUTH2_TOKEN_MISSING;
import static io.trino.plugin.iceberg.catalog.rest.IcebergRestCatalogConfig.SessionType.USER;
import static io.trino.plugin.iceberg.catalog.rest.PassthroughTokenResolver.EXTRA_CREDENTIAL_TOKEN_KEY;
import static io.trino.plugin.iceberg.catalog.rest.RestCatalogTestUtils.backendCatalog;
import static io.trino.type.InternalTypeManager.TESTING_TYPE_MANAGER;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

        catalog = buildCatalog(MissingTokenBehavior.REJECT);
    }

    private TrinoCatalog buildCatalog(MissingTokenBehavior missingTokenBehavior)
    {
        return new TrinoRestCatalog(
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
                true,
                missingTokenBehavior);
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

    @Test
    public void testRejectFailsBeforeAnyCatalogCall()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        TrinoCatalog rejectCatalog = buildCatalog(MissingTokenBehavior.REJECT);

        assertThatThrownBy(() -> rejectCatalog.listNamespaces(tokenlessSession("alice")))
                .isInstanceOf(TrinoException.class)
                .hasFieldOrPropertyWithValue("errorCode", ICEBERG_OAUTH2_TOKEN_MISSING.toErrorCode())
                .hasMessageContaining(EXTRA_CREDENTIAL_TOKEN_KEY);

        // The query must fail before reaching the catalog
        assertThat(capturedRequestLines).isEmpty();
    }

    @Test
    public void testFallbackUsesStaticServiceAccountBearer()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        TrinoCatalog fallbackCatalog = buildCatalog(MissingTokenBehavior.FALLBACK);

        fallbackCatalog.listNamespaces(tokenlessSession("alice"));

        // The subject token was dropped, so the request runs under the static bootstrap identity
        assertThat(capturedAuthorizationHeaders).contains("Bearer static-bootstrap-token");
        // No per-user token exchange occurs
        assertThat(capturedRequestLines)
                .noneMatch(line -> line.contains("oauth/tokens") || line.contains("v1/oauth"));
    }

    @Test
    public void testFallbackStripsBlankTokenKey()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        TrinoCatalog fallbackCatalog = buildCatalog(MissingTokenBehavior.FALLBACK);

        // A blank token under the passthrough key is treated as absent; it must be stripped so it
        // cannot reach the downstream library, and the request runs under the static identity.
        fallbackCatalog.listNamespaces(sessionForUser("alice", "   "));

        assertThat(capturedAuthorizationHeaders).contains("Bearer static-bootstrap-token");
        assertThat(capturedAuthorizationHeaders).doesNotContain("Bearer    ", "Bearer ");
    }

    @Test
    public void testSmuggledRawKeyBearerIsRejected()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        TrinoCatalog rejectCatalog = buildCatalog(MissingTokenBehavior.REJECT);

        // A client placing a bearer under the library's raw 'token' key (not the passthrough key) must be
        // treated as tokenless and rejected before any catalog call — the smuggled bearer must not reach
        // the wire.
        assertThatThrownBy(() -> rejectCatalog.listNamespaces(sessionWithCredentials("mallory", ImmutableMap.of(OAuth2Properties.TOKEN, "smuggled-bearer"))))
                .isInstanceOf(TrinoException.class)
                .hasFieldOrPropertyWithValue("errorCode", ICEBERG_OAUTH2_TOKEN_MISSING.toErrorCode());

        assertThat(capturedRequestLines).isEmpty();
        assertThat(capturedAuthorizationHeaders).doesNotContain("Bearer smuggled-bearer");
    }

    @Test
    public void testCollidingRawKeyDoesNotOverridePassthroughToken()
    {
        capturedAuthorizationHeaders.clear();
        capturedRequestLines.clear();

        // The passthrough token must win over a colliding raw 'token' key, with no internal error.
        catalog.listNamespaces(sessionWithCredentials("alice", ImmutableMap.of(
                EXTRA_CREDENTIAL_TOKEN_KEY, "user-token-alice",
                OAuth2Properties.TOKEN, "smuggled-bearer")));

        assertThat(capturedAuthorizationHeaders).contains("Bearer user-token-alice");
        assertThat(capturedAuthorizationHeaders).doesNotContain("Bearer smuggled-bearer");
    }

    private static ConnectorSession sessionForUser(String user, String token)
    {
        return sessionWithCredentials(user, ImmutableMap.of(EXTRA_CREDENTIAL_TOKEN_KEY, token));
    }

    private static ConnectorSession sessionWithCredentials(String user, Map<String, String> extraCredentials)
    {
        return TestingConnectorSession.builder()
                .setIdentity(ConnectorIdentity.forUser(user)
                        .withExtraCredentials(extraCredentials)
                        .build())
                .build();
    }

    private static ConnectorSession tokenlessSession(String user)
    {
        return TestingConnectorSession.builder()
                .setIdentity(ConnectorIdentity.forUser(user).build())
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
