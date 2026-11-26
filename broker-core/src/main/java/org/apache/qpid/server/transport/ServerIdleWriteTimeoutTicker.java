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
 *
 */

package org.apache.qpid.server.transport;

import org.apache.qpid.server.transport.network.Ticker;
import org.apache.qpid.server.transport.network.TransportActivity;

public class ServerIdleWriteTimeoutTicker implements Ticker
{
    private final ServerNetworkConnection _connection;
    private final TransportActivity _transport;
    private final int _writeDelay;

    public ServerIdleWriteTimeoutTicker(final TransportActivity transport, final int writeDelay)
    {
        this(null, transport, writeDelay);
    }

    public ServerIdleWriteTimeoutTicker(final ServerNetworkConnection connection,
                                        final TransportActivity transport,
                                        final int writeDelay)
    {
        if (writeDelay <= 0)
        {
            throw new IllegalArgumentException("Write delay should be positive");
        }

        _connection = connection;
        _transport = transport;
        _writeDelay = writeDelay;
    }

    @Override
    public int getTimeToNextTick(final long currentTime)
    {
        if (_connection != null && _connection.hasPendingWrites())
        {
            // A heartbeat would sit behind the output that is already waiting to be written.
            return _writeDelay;
        }
        final long writeTime = _transport.getLastWriteTime() + _writeDelay;
        return (int) (writeTime - currentTime);
    }

    @Override
    public int tick(final long currentTime)
    {
        final int timeToNextTick = getTimeToNextTick(currentTime);
        if (timeToNextTick <= 0)
        {
            _transport.writerIdle();
        }

        return timeToNextTick;
    }
}
