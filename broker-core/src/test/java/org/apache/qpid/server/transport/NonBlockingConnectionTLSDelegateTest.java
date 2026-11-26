/*
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.qpid.server.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import org.apache.qpid.server.bytebuffer.QpidByteBuffer;
import org.apache.qpid.server.model.port.AmqpPort;
import org.apache.qpid.test.utils.UnitTestBase;

class NonBlockingConnectionTLSDelegateTest extends UnitTestBase
{
    private static final int NETWORK_BUFFER_SIZE = 4096;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void handshakeOutputIsFlushedBeforeWaitingForPeerInput(final boolean multipleBatches) throws Exception
    {
        final NonBlockingConnection parent = mock(NonBlockingConnection.class);
        final SSLEngine engine = mock(SSLEngine.class);
        final AtomicReference<SSLEngineResult.HandshakeStatus> status =
                new AtomicReference<>(SSLEngineResult.HandshakeStatus.NEED_WRAP);
        final AtomicBoolean fillFirstBatch = new AtomicBoolean(multipleBatches);
        when(engine.getHandshakeStatus()).thenAnswer(invocation -> status.get());
        when(engine.wrap(any(ByteBuffer[].class), any(ByteBuffer.class))).thenAnswer(invocation ->
        {
            final ByteBuffer output = invocation.getArgument(1);
            if (fillFirstBatch.getAndSet(false))
            {
                output.put(new byte[NETWORK_BUFFER_SIZE]);
                return new SSLEngineResult(SSLEngineResult.Status.OK, status.get(), 0, NETWORK_BUFFER_SIZE);
            }
            output.put((byte) 1);
            status.set(SSLEngineResult.HandshakeStatus.NEED_UNWRAP);
            return new SSLEngineResult(SSLEngineResult.Status.OK, status.get(), 0, 1);
        });
        final NonBlockingConnectionTLSDelegate delegate = createDelegate(parent, engine, false);
        try (final QpidByteBuffer application = QpidByteBuffer.wrap(new byte[128]))
        {
            final List<QpidByteBuffer> buffers = List.of(application);
            final NonBlockingConnectionDelegate.WriteResult blockedWrite = delegate.doWrite(buffers);
            assertFalse(blockedWrite.isComplete());
            assertEquals(0, blockedWrite.getSocketBytesWritten());
            assertEquals(multipleBatches ? NETWORK_BUFFER_SIZE : 1, delegate.getBufferedOutputSize());
            assertFalse(delegate.needsReadForWrite(), "Buffered handshake output must still select for writing");

            allowWrites(parent);

            if (multipleBatches)
            {
                final NonBlockingConnectionDelegate.WriteResult drained = delegate.doWrite(List.of());
                assertFalse(drained.isComplete(), "NEED_WRAP must remain writable after the first batch drains");
                assertEquals(NETWORK_BUFFER_SIZE, drained.getSocketBytesWritten());
                assertFalse(delegate.needsReadForWrite());
                verify(engine).wrap(any(ByteBuffer[].class), any(ByteBuffer.class));
            }
            assertFalse(delegate.doWrite(buffers).isComplete());
            assertTrue(application.hasRemaining(), "Application bytes must wait for the peer handshake response");
            assertTrue(delegate.needsReadForWrite(), "A writable socket cannot advance NEED_UNWRAP");
            assertEquals(0, delegate.getBufferedOutputSize());
            if (multipleBatches)
            {
                final ArgumentCaptor<ByteBuffer> output = ArgumentCaptor.captor();
                verify(engine, times(2)).wrap(any(ByteBuffer[].class), output.capture());
                final List<ByteBuffer> batches = output.getAllValues();
                assertSame(batches.get(0), batches.get(1), "TLS must reuse the drained direct buffer");
            }
        }
        finally
        {
            delegate.shutdownInput();
            delegate.shutdownOutput();
        }
    }

    @Test
    void testLoopBreakerCountsWrapsAcrossOutputBatches() throws Exception
    {
        final NonBlockingConnection parent = mock();
        final SSLEngine engine = mock();
        final SSLEngineResult.HandshakeStatus needWrap = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        when(engine.getHandshakeStatus()).thenReturn(needWrap);
        when(engine.wrap(any(ByteBuffer[].class), any(ByteBuffer.class))).thenAnswer(invocation ->
        {
            final ByteBuffer output = invocation.getArgument(1);
            output.position(output.limit());
            return new SSLEngineResult(SSLEngineResult.Status.OK, needWrap, 0, NETWORK_BUFFER_SIZE);
        });
        allowWrites(parent);

        final NonBlockingConnectionTLSDelegate delegate = createDelegate(parent, engine, true);
        try
        {
            final NonBlockingConnectionDelegate.WriteResult firstBatch = delegate.doWrite(List.of());
            assertFalse(firstBatch.isComplete());
            assertEquals(NETWORK_BUFFER_SIZE, firstBatch.getSocketBytesWritten());
            assertThrows(SSLException.class, () -> delegate.doWrite(List.of()));
        }
        finally
        {
            delegate.shutdownInput();
            delegate.shutdownOutput();
        }
    }

    @Test
    void testLoopBreakerAllowsApplicationProgressAcrossBatches() throws IOException
    {
        final NonBlockingConnection parent = mock();
        final SSLEngine engine = mock();
        final SSLEngineResult.HandshakeStatus idle = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        when(engine.getHandshakeStatus()).thenReturn(idle);
        when(engine.wrap(any(ByteBuffer[].class), any(ByteBuffer.class))).thenAnswer(invocation ->
        {
            final ByteBuffer source = invocation.<ByteBuffer[]>getArgument(0)[0];
            final ByteBuffer output = invocation.getArgument(1);
            final int count = Math.min(source.remaining(), output.remaining());
            source.position(source.position() + count);
            output.position(output.position() + count);
            return new SSLEngineResult(SSLEngineResult.Status.OK, idle, count, count);
        });
        allowWrites(parent);

        final NonBlockingConnectionTLSDelegate delegate = createDelegate(parent, engine, true);
        try (final QpidByteBuffer application = QpidByteBuffer.allocate(2 * NETWORK_BUFFER_SIZE))
        {
            final List<QpidByteBuffer> buffers = List.of(application);
            final NonBlockingConnectionDelegate.WriteResult first = delegate.doWrite(buffers);
            final NonBlockingConnectionDelegate.WriteResult second = delegate.doWrite(buffers);
            assertFalse(first.isComplete());
            assertTrue(second.isComplete());
            assertEquals(NETWORK_BUFFER_SIZE, first.getSocketBytesWritten());
            assertEquals(NETWORK_BUFFER_SIZE, second.getSocketBytesWritten());
        }
        finally
        {
            delegate.shutdownInput();
            delegate.shutdownOutput();
        }
    }

    @Test
    void testWrapWithoutProgressFails() throws IOException
    {
        final NonBlockingConnection parent = mock();
        final SSLEngine engine = mock();
        final SSLEngineResult.HandshakeStatus needWrap = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        when(engine.getHandshakeStatus()).thenReturn(needWrap);
        when(engine.wrap(any(ByteBuffer[].class), any(ByteBuffer.class)))
                .thenReturn(new SSLEngineResult(SSLEngineResult.Status.OK, needWrap, 0, 0));

        final NonBlockingConnectionTLSDelegate delegate = createDelegate(parent, engine, false);
        try
        {
            assertThrows(SSLException.class, () -> delegate.doWrite(List.of()));
        }
        finally
        {
            delegate.shutdownInput();
            delegate.shutdownOutput();
        }
    }

    @Test
    void testFailedSocketWriteRetainsCiphertext() throws IOException
    {
        final NonBlockingConnection parent = mock();
        final SSLEngine engine = mock();
        final AtomicReference<SSLEngineResult.HandshakeStatus> status =
                new AtomicReference<>(SSLEngineResult.HandshakeStatus.NEED_WRAP);
        when(engine.getHandshakeStatus()).thenAnswer(invocation -> status.get());
        when(engine.wrap(any(ByteBuffer[].class), any(ByteBuffer.class))).thenAnswer(invocation ->
        {
            final ByteBuffer output = invocation.getArgument(1);
            output.put((byte) 1);
            status.set(SSLEngineResult.HandshakeStatus.NEED_UNWRAP);
            return new SSLEngineResult(SSLEngineResult.Status.OK, status.get(), 0, 1);
        });
        when(parent.writeToTransport(any(QpidByteBuffer.class))).thenThrow(new IOException("Socket write failed"));

        final NonBlockingConnectionTLSDelegate delegate = createDelegate(parent, engine, false);
        try
        {
            assertThrows(IOException.class, () -> delegate.doWrite(List.of()));
            assertEquals(1, delegate.getBufferedOutputSize());

            allowWrites(parent);
            final NonBlockingConnectionDelegate.WriteResult retry = delegate.doWrite(List.of());
            assertEquals(1, retry.getSocketBytesWritten());
            assertEquals(0, delegate.getBufferedOutputSize());
            assertTrue(delegate.needsReadForWrite());
            verify(engine).wrap(any(ByteBuffer[].class), any(ByteBuffer.class));
        }
        finally
        {
            delegate.shutdownInput();
            delegate.shutdownOutput();
        }
    }

    private NonBlockingConnectionTLSDelegate createDelegate(final NonBlockingConnection parent,
                                                           final SSLEngine engine,
                                                           final boolean diagnoseLooping)
    {
        final SSLSession session = mock(SSLSession.class);
        when(session.getPacketBufferSize()).thenReturn(1024);
        when(engine.getSession()).thenReturn(session);
        when(engine.getEnabledProtocols()).thenReturn(new String[]{"TLSv1.3"});
        when(engine.getSupportedProtocols()).thenReturn(new String[]{"TLSv1.3"});
        when(engine.getEnabledCipherSuites()).thenReturn(new String[]{"TLS_AES_128_GCM_SHA256"});
        when(engine.getSupportedCipherSuites()).thenReturn(new String[]{"TLS_AES_128_GCM_SHA256"});
        final SSLContext context = mock(SSLContext.class);
        when(context.createSSLEngine()).thenReturn(engine);
        final AmqpPort<?> port = mock(AmqpPort.class);
        when(port.getSSLContext()).thenReturn(context);
        when(port.getNetworkBufferSize()).thenReturn(NETWORK_BUFFER_SIZE);
        when(port.getContextValue(Boolean.class, AmqpPort.PORT_DIAGNOSIS_OF_SSL_ENGINE_LOOPING))
                .thenReturn(diagnoseLooping);
        when(port.getContextValue(Integer.class, AmqpPort.PORT_DIAGNOSIS_OF_SSL_ENGINE_LOOPING_WARN_THRESHOLD))
                .thenReturn(1);
        when(port.getContextValue(Integer.class, AmqpPort.PORT_DIAGNOSIS_OF_SSL_ENGINE_LOOPING_BREAK_THRESHOLD))
                .thenReturn(1);
        return new NonBlockingConnectionTLSDelegate(parent, port);
    }

    private void allowWrites(final NonBlockingConnection parent) throws IOException
    {
        doAnswer(invocation ->
        {
            final QpidByteBuffer encrypted = invocation.getArgument(0);
            final long written = encrypted.remaining();
            encrypted.position(encrypted.limit());
            return written;
        }).when(parent).writeToTransport(any(QpidByteBuffer.class));
    }
}
