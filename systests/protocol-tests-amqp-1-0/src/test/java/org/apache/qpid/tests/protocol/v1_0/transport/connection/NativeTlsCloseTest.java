/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for
 * the specific language governing permissions and limitations
 * under the License.
 *
 */
package org.apache.qpid.tests.protocol.v1_0.transport.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import io.netty.util.concurrent.Future;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.apache.qpid.server.model.Connection;
import org.apache.qpid.server.model.Transport;
import org.apache.qpid.server.model.port.AmqpPort;
import org.apache.qpid.server.protocol.v1_0.type.transport.Close;
import org.apache.qpid.test.utils.tls.AltNameType;
import org.apache.qpid.test.utils.tls.AlternativeName;
import org.apache.qpid.test.utils.tls.KeyCertificatePair;
import org.apache.qpid.test.utils.tls.PrivateKeyEntry;
import org.apache.qpid.test.utils.tls.TlsResource;
import org.apache.qpid.test.utils.tls.TlsResourceBuilder;
import org.apache.qpid.tests.protocol.v1_0.FrameTransport;
import org.apache.qpid.tests.protocol.v1_0.Interaction;
import org.apache.qpid.tests.utils.BrokerAdmin;
import org.apache.qpid.tests.utils.BrokerAdminUsingTestBase;
import org.apache.qpid.tests.utils.BrokerSpecific;
import org.apache.qpid.tests.utils.ConfigItem;
import org.apache.qpid.tests.utils.EmbeddedBrokerPerClassAdminImpl;

@BrokerSpecific(kind = BrokerAdmin.KIND_BROKER_J)
@ConfigItem(name = Connection.CLOSE_RESPONSE_TIMEOUT, value = "10000")
public class NativeTlsCloseTest extends BrokerAdminUsingTestBase
{
    private static final long AWAIT_TIMEOUT_SECONDS = 5L;

    @ParameterizedTest
    @CsvSource({"TLSv1.2, true, false", "TLSv1.2, false, false", "TLSv1.3, true, false", "TLSv1.3, false, false",
                "TLSv1.2, true, true", "TLSv1.2, false, true", "TLSv1.3, true, true", "TLSv1.3, false, true"})
    public void peerReceivesTlsCloseNotifyAfterAmqpClose(final String tlsProtocol, final boolean brokerInitiated,
                                                       final boolean zeroFinalWriteTimeout)
            throws Exception
    {
        final BrokerAdmin brokerAdmin = getBrokerAdmin();
        assumeTrue(brokerAdmin instanceof EmbeddedBrokerPerClassAdminImpl, "Native TLS requires an embedded broker");
        assumeTrue(brokerAdmin.isAnonymousSupported());
        assumeTrue(!brokerInitiated || brokerAdmin.isConnectionManagementSupported());
        final EmbeddedBrokerPerClassAdminImpl admin = (EmbeddedBrokerPerClassAdminImpl) brokerAdmin;
        final AlternativeName alternativeName = new AlternativeName(AltNameType.DNS_NAME, "localhost");
        final KeyCertificatePair server = TlsResourceBuilder.createSelfSigned("CN=localhost", alternativeName);
        try (final TlsResource tls = new TlsResource())
        {
            final String portName = "SSL-" + server.certificate().getSerialNumber().toString(16);
            final String keyStore = tls.createKeyStoreAsDataUrl(new PrivateKeyEntry(tls.getPrivateKeyAlias(), server));
            final Map<String, String> portContext =
                    zeroFinalWriteTimeout ? Map.of(AmqpPort.FINAL_WRITE_TIMEOUT, "0") : Map.of();
            final InetSocketAddress address =
                    admin.createTlsAmqpPort(Transport.SSL, portName, keyStore, tls.getSecret(), portContext);
            final SslContext client = SslContextBuilder.forClient().sslProvider(SslProvider.JDK)
                    .trustManager(server.certificate()).protocols(tlsProtocol).endpointIdentificationAlgorithm("HTTPS")
                    .build();

            try (final TlsFrameTransport transport = new TlsFrameTransport(admin, address, client))
            {
                transport.connect();
                final String containerId = getFullTestName();
                final Interaction interaction = transport.newInteraction().openContainerId(containerId).negotiateOpen();
                assertEquals(tlsProtocol, transport._sslHandler.engine().getSession().getProtocol());

                if (brokerInitiated)
                {
                    admin.closeConnectionAsync(containerId);
                    interaction.consumeResponse(Close.class).close().sync();
                }
                else
                {
                    interaction.close().consumeResponse(Close.class);
                }

                final Future<Channel> tlsClose = transport._sslHandler.sslCloseFuture();
                assertTrue(tlsClose.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                        "Timed out waiting for close_notify");
                assertTrue(tlsClose.isSuccess(), () -> "Expected close_notify before TCP closure: " + tlsClose.cause());
                assertTrue(transport._tcpClose.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                        "TCP remained open after close_notify");
            }
        }
    }

    private static final class TlsFrameTransport extends FrameTransport
    {
        private final SslContext _tlsContext;
        private volatile SslHandler _sslHandler;
        private volatile ChannelFuture _tcpClose;

        private TlsFrameTransport(final BrokerAdmin admin, final InetSocketAddress address, final SslContext tlsContext)
        {
            super(admin, BrokerAdmin.PortType.ANONYMOUS_AMQP, address);
            _tlsContext = tlsContext;
        }

        @Override
        protected void buildInputOutputPipeline(final ChannelPipeline pipeline)
        {
            final InetSocketAddress address = getBrokerAddress();
            _sslHandler = _tlsContext.newHandler(pipeline.channel().alloc(), address.getHostString(),
                    address.getPort());
            _tcpClose = pipeline.channel().closeFuture();
            pipeline.addLast(_sslHandler);
            super.buildInputOutputPipeline(pipeline);
        }
    }
}
