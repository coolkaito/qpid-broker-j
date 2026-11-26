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

import java.io.IOException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.qpid.server.bytebuffer.QpidByteBuffer;
import org.apache.qpid.server.model.port.AmqpPort;
import org.apache.qpid.server.transport.network.security.ssl.SSLUtil;
import org.apache.qpid.server.util.ServerScopedRuntimeException;

public class NonBlockingConnectionTLSDelegate implements NonBlockingConnectionDelegate
{
    private static final Logger LOGGER = LoggerFactory.getLogger(NonBlockingConnectionTLSDelegate.class);

    private final SSLEngine _sslEngine;
    private final NonBlockingConnection _parent;
    private final int _networkBufferSize;
    private SSLEngineResult _status;
    private volatile int _encryptedOutputSize;
    private Principal _principal;
    private Certificate _peerCertificate;
    private boolean _principalChecked;
    private volatile boolean _hostChecked;
    private volatile boolean _needsReadForWrite;
    private boolean _needsMoreNetworkData;
    private QpidByteBuffer _netInputBuffer;
    private QpidByteBuffer _netOutputBuffer;
    private QpidByteBuffer _applicationBuffer;
    private int _consecutiveWrapsWithoutProgress;
    private final boolean _enableDiagnosisOfSslEngineLooping;
    private final long _diagnosisOfSslEngineLoopingWarnThreshold;
    private final long _diagnosisOfSslEngineLoopingBreakThreshold;

    public NonBlockingConnectionTLSDelegate(NonBlockingConnection parent, AmqpPort port)
    {
        _parent = parent;
        _sslEngine = createSSLEngine(port);
        _networkBufferSize = port.getNetworkBufferSize();

        final int tlsPacketBufferSize = _sslEngine.getSession().getPacketBufferSize();
        if (tlsPacketBufferSize > _networkBufferSize)
        {
            throw new ServerScopedRuntimeException("TLS implementation packet buffer size (" + tlsPacketBufferSize
                    + ") is greater then broker network buffer size (" + _networkBufferSize + ")");
        }

        _netInputBuffer = QpidByteBuffer.allocateDirect(_networkBufferSize);
        _applicationBuffer = QpidByteBuffer.allocateDirect(_networkBufferSize);
        _netOutputBuffer = QpidByteBuffer.allocateDirect(_networkBufferSize);
        _enableDiagnosisOfSslEngineLooping = port.getContextValue(Boolean.class, AmqpPort.PORT_DIAGNOSIS_OF_SSL_ENGINE_LOOPING);
        _diagnosisOfSslEngineLoopingWarnThreshold = port.getContextValue(Integer.class, AmqpPort.PORT_DIAGNOSIS_OF_SSL_ENGINE_LOOPING_WARN_THRESHOLD);
        _diagnosisOfSslEngineLoopingBreakThreshold = port.getContextValue(Integer.class, AmqpPort.PORT_DIAGNOSIS_OF_SSL_ENGINE_LOOPING_BREAK_THRESHOLD);
    }

    @Override
    public boolean readyForRead()
    {
        return _sslEngine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP;
    }

    @Override
    public boolean processData() throws IOException
    {
        if(!_hostChecked)
        {
            try (QpidByteBuffer buffer = _netInputBuffer.duplicate())
            {
                buffer.flip();
                if (SSLUtil.isSufficientToDetermineClientSNIHost(buffer))
                {
                    final SNIHostName hostName = getSNIHostName(buffer);
                    if (hostName != null)
                    {
                        _parent.setSelectedHost(hostName.getAsciiName());
                        SSLParameters sslParameters = _sslEngine.getSSLParameters();
                        sslParameters.setServerNames(Collections.singletonList(hostName));
                        _sslEngine.setSSLParameters(sslParameters);
                    }
                    _hostChecked = true;
                }
                else
                {
                    _needsMoreNetworkData = true;
                    return false;
                }
            }
        }
        _netInputBuffer.flip();
        boolean readData = false;
        boolean tasksRun;
        int oldNetBufferPos;
        do
        {
            int oldAppBufPos = _applicationBuffer.position();
            oldNetBufferPos = _netInputBuffer.position();

            _status = QpidByteBuffer.decryptSSL(_sslEngine, _netInputBuffer, _applicationBuffer);
            _needsMoreNetworkData = _status.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW;
            if (_status.getStatus() == SSLEngineResult.Status.CLOSED)
            {
                int remaining = _netInputBuffer.remaining();
                _netInputBuffer.position(_netInputBuffer.limit());
                // We'd usually expect no more bytes to be sent following a close_notify
                LOGGER.debug("SSLEngine closed, discarded {} byte(s)", remaining);
            }

            tasksRun = runSSLEngineTasks(_status, false);
            if(_applicationBuffer.position() > oldAppBufPos)
            {
                readData = true;
            }
            _applicationBuffer.flip();

            _parent.processAmqpData(_applicationBuffer);

            restoreApplicationBufferForWrite();

        }
        while((_netInputBuffer.hasRemaining() && (_netInputBuffer.position()>oldNetBufferPos)) || tasksRun);

        if(_netInputBuffer.hasRemaining())
        {
            _netInputBuffer.compact();
        }
        else
        {
            _netInputBuffer.clear();
        }
        return readData;
    }

    private SNIHostName getSNIHostName(final QpidByteBuffer buffer)
    {
        final String name = SSLUtil.getServerNameFromTLSClientHello(buffer);
        if (name != null)
        {
            return SSLUtil.createSNIHostName(name);
        }
        return null;
    }

    @Override
    public WriteResult doWrite(final Collection<QpidByteBuffer> buffers) throws IOException
    {
        long totalConsumed = 0;
        // Reuse the output buffer only after all of its ciphertext has been written.
        if (_encryptedOutputSize == 0)
        {
            _netOutputBuffer.clear();
            try
            {
                totalConsumed = wrapOutput(buffers);
            }
            finally
            {
                _netOutputBuffer.flip();
                _encryptedOutputSize = _netOutputBuffer.remaining();
            }
        }
        if (_parent.checkForWriteAbort())
        {
            return new WriteResult(false, totalConsumed, 0);
        }

        final long bytesWritten;
        try
        {
            bytesWritten = _netOutputBuffer.hasRemaining() ? _parent.writeToTransport(_netOutputBuffer) : 0;
        }
        finally
        {
            _encryptedOutputSize = _netOutputBuffer.remaining();
        }

        final SSLEngineResult.HandshakeStatus handshakeStatus = _sslEngine.getHandshakeStatus();
        final boolean outputDrained = !_netOutputBuffer.hasRemaining();
        _needsReadForWrite = outputDrained && handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        boolean complete = outputDrained && handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_WRAP;
        if (complete)
        {
            for (final QpidByteBuffer buffer : buffers)
            {
                if (buffer.hasRemaining())
                {
                    complete = false;
                    break;
                }
            }
        }
        return new WriteResult(complete, totalConsumed, bytesWritten);
    }

    @Override
    public int getBufferedOutputSize()
    {
        return _encryptedOutputSize;
    }

    @Override
    public boolean needsReadForWrite()
    {
        return _needsReadForWrite;
    }

    protected void restoreApplicationBufferForWrite()
    {
        try (QpidByteBuffer oldApplicationBuffer = _applicationBuffer)
        {
            int unprocessedDataLength = _applicationBuffer.remaining();
            _applicationBuffer.limit(_applicationBuffer.capacity());
            _applicationBuffer = _applicationBuffer.slice();
            _applicationBuffer.limit(unprocessedDataLength);
        }
        if (_applicationBuffer.limit() <= _applicationBuffer.capacity() - _sslEngine.getSession().getApplicationBufferSize())
        {
            _applicationBuffer.position(_applicationBuffer.limit());
            _applicationBuffer.limit(_applicationBuffer.capacity());
        }
        else
        {
            try (QpidByteBuffer currentBuffer = _applicationBuffer)
            {
                int newBufSize;
                if (currentBuffer.capacity() < _networkBufferSize)
                {
                    newBufSize = _networkBufferSize;
                }
                else
                {
                    newBufSize = currentBuffer.capacity() + _networkBufferSize;
                    _parent.reportUnexpectedByteBufferSizeUsage();
                }

                _applicationBuffer = QpidByteBuffer.allocateDirect(newBufSize);
                _applicationBuffer.put(currentBuffer);
            }
        }

    }

    private long wrapOutput(final Collection<QpidByteBuffer> buffers) throws SSLException
    {
        long totalConsumed = 0;
        boolean encrypted = false;
        do
        {
            if (_parent.checkForWriteAbort())
            {
                return totalConsumed;
            }
            final SSLEngineResult.HandshakeStatus handshakeStatus = _sslEngine.getHandshakeStatus();
            if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            {
                _consecutiveWrapsWithoutProgress = 0;
                break;
            }
            final int packetBufferSize = _sslEngine.getSession().getPacketBufferSize();
            if (_netOutputBuffer.remaining() < packetBufferSize)
            {
                if (packetBufferSize > _networkBufferSize)
                {
                    throw new SSLException("TLS packet buffer size " + packetBufferSize +
                            " exceeds network buffer size " + _networkBufferSize);
                }
                break;
            }

            _status = QpidByteBuffer.encryptSSL(_sslEngine, buffers, _netOutputBuffer);
            if (_status.getStatus() == SSLEngineResult.Status.CLOSED)
            {
                throw new SSLException(String.format("SSLEngine.wrap operation could not be completed because" +
                                " it was already closed (status %s, handshake status %s)",
                        _status.getStatus(), _status.getHandshakeStatus()));
            }
            // QPID-8489: workaround for JDK 8 bug to avoid tight looping for half closed connections
            // Additional info: https://bugs.openjdk.java.net/browse/JDK-8240071,
            // http://mail.openjdk.java.net/pipermail/security-dev/2019-January/019142.html
            final int produced = _status.bytesProduced();
            if (produced < 1 && _status.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP &&
                    !_sslEngine.isOutboundDone() && _sslEngine.isInboundDone())
            {
                throw new SSLException(String.format("SSLEngine.wrap produced 0 bytes (status %s, handshake status %s)",
                        _status.getStatus(), _status.getHandshakeStatus()));
            }
            encrypted = produced > 0;
            final int consumed = _status.bytesConsumed();
            totalConsumed += consumed;
            if (consumed > 0)
            {
                _parent.releaseConsumedBuffers(buffers);
            }
            final boolean tasksRun = runSSLEngineTasks(_status, true);
            if (_parent.checkForWriteAbort())
            {
                return totalConsumed;
            }
            if (!encrypted && consumed == 0 && !tasksRun &&
                    handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP &&
                    _sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP &&
                    (_status.getStatus() != SSLEngineResult.Status.BUFFER_OVERFLOW || _netOutputBuffer.position() == 0))
            {
                throw new SSLException("SSLEngine.wrap made no progress while waiting to produce handshake output");
            }
            if (_enableDiagnosisOfSslEngineLooping)
            {
                if (consumed > 0 || tasksRun || handshakeStatus != _sslEngine.getHandshakeStatus() ||
                        (!encrypted && _status.getStatus() != SSLEngineResult.Status.BUFFER_OVERFLOW))
                {
                    _consecutiveWrapsWithoutProgress = 0;
                }
                else if (encrypted)
                {
                    final int consecutiveWraps = ++_consecutiveWrapsWithoutProgress;
                    if (consecutiveWraps > _diagnosisOfSslEngineLoopingWarnThreshold)
                    {
                        LOGGER.warn("SSLEngine looping detected, status: {}, handshake status: {}, " +
                                        "bytes consumed: {}, bytes produced: {}, peer host: {}, peer port: {}",
                                _status.getStatus(), _status.getHandshakeStatus(), consumed, produced,
                                _sslEngine.getPeerHost(), _sslEngine.getPeerPort());
                    }
                    if (consecutiveWraps > _diagnosisOfSslEngineLoopingBreakThreshold)
                    {
                        throw new SSLException("SSLEngine looping detected, executing circuit breaker");
                    }
                }
            }
        }
        while (encrypted);

        return totalConsumed;
    }

    private boolean runSSLEngineTasks(final SSLEngineResult status, final boolean writing)
    {
        if(status.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK)
        {
            Runnable task;
            while ((!writing || !_parent.checkForWriteAbort()) && (task = _sslEngine.getDelegatedTask()) != null)
            {
                task.run();
            }

            return true;
        }

        return false;
    }

    @Override
    public Principal getPeerPrincipal()
    {
        checkPeerPrincipal();
        return _principal;
    }

    @Override
    public Certificate getPeerCertificate()
    {
        checkPeerPrincipal();
        return _peerCertificate;
    }

    @Override
    public boolean needsWork()
    {
        return !_needsMoreNetworkData && _sslEngine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
    }

    private synchronized void checkPeerPrincipal()
    {
        if (!_principalChecked)
        {
            try
            {
                _principal = _sslEngine.getSession().getPeerPrincipal();
                final Certificate[] peerCertificates =
                        _sslEngine.getSession().getPeerCertificates();
                if (peerCertificates != null && peerCertificates.length > 0)
                {
                    _peerCertificate = peerCertificates[0];
                }
            }
            catch (SSLPeerUnverifiedException e)
            {
                _principal = null;
                _peerCertificate = null;
            }

            _principalChecked = true;
        }
    }

    private SSLEngine createSSLEngine(AmqpPort<?> port)
    {
        SSLEngine sslEngine = port.getSSLContext().createSSLEngine();
        sslEngine.setUseClientMode(false);
        SSLUtil.updateEnabledTlsProtocols(sslEngine, port.getTlsProtocolAllowList(), port.getTlsProtocolDenyList());
        SSLUtil.updateEnabledCipherSuites(sslEngine, port.getTlsCipherSuiteAllowList(), port.getTlsCipherSuiteDenyList());
        if(port.getTlsCipherSuiteAllowList() != null && !port.getTlsCipherSuiteAllowList().isEmpty())
        {
            SSLParameters sslParameters = sslEngine.getSSLParameters();
            sslParameters.setUseCipherSuitesOrder(true);
            sslEngine.setSSLParameters(sslParameters);
        }

        if(port.getNeedClientAuth())
        {
            sslEngine.setNeedClientAuth(true);
        }
        else if(port.getWantClientAuth())
        {
            sslEngine.setWantClientAuth(true);
        }
        return sslEngine;
    }

    @Override
    public QpidByteBuffer getNetInputBuffer()
    {
        return _netInputBuffer;
    }

    @Override
    public void shutdownInput()
    {
        if (_netInputBuffer != null)
        {
            _netInputBuffer.dispose();
            _netInputBuffer = null;
        }

        if (_applicationBuffer != null)
        {
            _applicationBuffer.dispose();
            _applicationBuffer = null;
        }
    }

    @Override
    public void shutdownOutput()
    {
        if (_netOutputBuffer != null)
        {
            _netOutputBuffer.dispose();
            _netOutputBuffer = null;
        }
        _encryptedOutputSize = 0;
        try
        {
            _sslEngine.closeOutbound();
            _sslEngine.closeInbound();
        }
        catch (SSLException e)
        {
            LOGGER.debug("Exception when closing SSLEngine", e);
        }

    }

    @Override
    public String getTransportInfo()
    {
        SSLSession session = _sslEngine.getSession();
        return session.getProtocol() + " ; " + session.getCipherSuite() ;
    }
}
