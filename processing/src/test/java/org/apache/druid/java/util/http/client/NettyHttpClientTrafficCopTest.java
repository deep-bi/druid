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

package org.apache.druid.java.util.http.client;

import com.google.common.util.concurrent.ListenableFuture;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.common.lifecycle.Lifecycle;
import org.apache.druid.java.util.http.client.pool.ResourceContainer;
import org.apache.druid.java.util.http.client.pool.ResourcePool;
import org.apache.druid.java.util.http.client.response.ClientResponse;
import org.apache.druid.java.util.http.client.response.HttpResponseHandler;
import org.apache.druid.java.util.http.client.response.StringFullResponseHandler;
import org.apache.druid.java.util.http.client.response.StringFullResponseHolder;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

public class NettyHttpClientTrafficCopTest
{
  private static final String CHUNKED_OK = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  private static final String LAST_CHUNK = "0\r\n\r\n";
  private static final String COMPLETE_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na";

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testLateAbortLeavesTheNextRequestOpen(final ResourcePool.Implementation implementation) throws Exception
  {
    try (final Fixture fixture = new Fixture(implementation)) {
      final ResponseHandler first = new ResponseHandler(false);
      final ListenableFuture<StringFullResponseHolder> firstResponse = fixture.client.go(fixture.request, first);
      fixture.server.send(COMPLETE_RESPONSE, true);
      Assertions.assertEquals("a", firstResponse.get(5, TimeUnit.SECONDS).getContent());
      final Channel channel = fixture.returnedChannel();

      final ResponseHandler second = new ResponseHandler(false);
      final ListenableFuture<StringFullResponseHolder> secondResponse = fixture.client.go(fixture.request, second);
      fixture.server.send(CHUNKED_OK + chunk("b"), false);
      Assertions.assertTrue(second.responseReceived.await(5, TimeUnit.SECONDS));

      first.trafficCop.get().abort();
      Assertions.assertTrue(channel.getPipeline().execute(() -> {}).await(5, TimeUnit.SECONDS));
      Assertions.assertTrue(channel.isConnected(), "A completed response must not close the reused connection");
      fixture.server.send(LAST_CHUNK, true);
      Assertions.assertEquals("b", secondResponse.get(5, TimeUnit.SECONDS).getContent());
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testQueuedAbortIsCheckedAfterCompletion(final ResourcePool.Implementation implementation) throws Exception
  {
    try (final Fixture fixture = new Fixture(implementation)) {
      final CountDownLatch completing = new CountDownLatch(1);
      final CountDownLatch allowCompletion = new CountDownLatch(1);
      final ResponseHandler first = new ResponseHandler(false)
      {
        @Override
        public ClientResponse<StringFullResponseHolder> done(final ClientResponse<StringFullResponseHolder> response)
        {
          completing.countDown();
          try {
            Assertions.assertTrue(allowCompletion.await(5, TimeUnit.SECONDS));
          }
          catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
          }
          return super.done(response);
        }
      };
      final ListenableFuture<StringFullResponseHolder> firstResponse = fixture.client.go(fixture.request, first);
      fixture.server.send(COMPLETE_RESPONSE, true);
      try {
        Assertions.assertTrue(completing.await(5, TimeUnit.SECONDS));
        // Queue the abort while the I/O thread is still inside done(), before it returns the connection.
        first.trafficCop.get().abort();
      }
      finally {
        allowCompletion.countDown();
      }
      Assertions.assertEquals("a", firstResponse.get(5, TimeUnit.SECONDS).getContent());

      final ListenableFuture<StringFullResponseHolder> secondResponse =
          fixture.client.go(fixture.request, new ResponseHandler(false));
      fixture.server.send(COMPLETE_RESPONSE, true);
      Assertions.assertEquals("a", secondResponse.get(5, TimeUnit.SECONDS).getContent());
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testLateResumeLeavesTheNextRequestSuspended(final ResourcePool.Implementation implementation) throws Exception
  {
    try (final Fixture fixture = new Fixture(implementation)) {
      // A non-chunked response completes in the same callback that suspends reads. Its watermark remains set.
      final ResponseHandler first = new ResponseHandler(true);
      final ListenableFuture<StringFullResponseHolder> firstResponse = fixture.client.go(fixture.request, first);
      fixture.server.send(COMPLETE_RESPONSE, true);
      Assertions.assertEquals("a", firstResponse.get(5, TimeUnit.SECONDS).getContent());
      final Channel channel = fixture.returnedChannel();

      final ResponseHandler second = new ResponseHandler(true);
      final ListenableFuture<StringFullResponseHolder> secondResponse = fixture.client.go(fixture.request, second);
      fixture.server.send(CHUNKED_OK, false);
      Assertions.assertTrue(second.responseReceived.await(5, TimeUnit.SECONDS));
      Assertions.assertTrue(channel.getPipeline().execute(() -> {}).await(5, TimeUnit.SECONDS));
      Assertions.assertFalse(channel.isReadable(), "The next response must have suspended reads");

      Assertions.assertEquals(0, first.trafficCop.get().resume(0));
      fixture.server.send(chunk("b"), false);
      Assertions.assertThrows(TimeoutException.class, () -> secondResponse.get(1, TimeUnit.SECONDS));

      second.trafficCop.get().resume(0);
      Assertions.assertTrue(second.chunkReceived.await(5, TimeUnit.SECONDS));
      Assertions.assertTrue(channel.getPipeline().execute(() -> {}).await(5, TimeUnit.SECONDS));
      Assertions.assertTrue(channel.isReadable(), "Reading a data chunk must not suspend reads again");
      fixture.server.send(LAST_CHUNK, true);
      Assertions.assertEquals("b", secondResponse.get(5, TimeUnit.SECONDS).getContent());
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testAbortStillClosesAnActiveResponse(final ResourcePool.Implementation implementation) throws Exception
  {
    try (final Fixture fixture = new Fixture(implementation)) {
      final ResponseHandler responseHandler = new ResponseHandler(false);
      final ListenableFuture<StringFullResponseHolder> response = fixture.client.go(fixture.request, responseHandler);
      fixture.server.send(CHUNKED_OK + chunk("a"), false);
      Assertions.assertTrue(responseHandler.responseReceived.await(5, TimeUnit.SECONDS));

      responseHandler.trafficCop.get().abort();
      Assertions.assertThrows(ExecutionException.class, () -> response.get(5, TimeUnit.SECONDS));
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testAbortAfterShutdownIsIgnored(final ResourcePool.Implementation implementation) throws Exception
  {
    try (final Fixture fixture = new Fixture(implementation)) {
      final ResponseHandler completed = new ResponseHandler(false);
      final ListenableFuture<StringFullResponseHolder> completedResponse = fixture.client.go(fixture.request, completed);
      fixture.server.send(COMPLETE_RESPONSE, true);
      Assertions.assertEquals("a", completedResponse.get(5, TimeUnit.SECONDS).getContent());
      fixture.returnedChannel();

      final ResponseHandler active = new ResponseHandler(false);
      final ListenableFuture<StringFullResponseHolder> activeResponse = fixture.client.go(fixture.request, active);
      fixture.server.send(CHUNKED_OK + chunk("b"), false);
      Assertions.assertTrue(active.responseReceived.await(5, TimeUnit.SECONDS));

      // Stopping the lifecycle shuts down the I/O worker, which then rejects scheduled tasks.
      fixture.lifecycle.stop();
      Assertions.assertThrows(ExecutionException.class, () -> activeResponse.get(5, TimeUnit.SECONDS));
      Assertions.assertDoesNotThrow(() -> completed.trafficCop.get().abort());
      Assertions.assertDoesNotThrow(() -> active.trafficCop.get().abort());
    }
  }

  private static String chunk(final String data)
  {
    return StringUtils.format("%x\r\n%s\r\n", data.length(), data);
  }

  private static class ResponseHandler implements HttpResponseHandler<StringFullResponseHolder, StringFullResponseHolder>
  {
    private final StringFullResponseHandler delegate = new StringFullResponseHandler(StandardCharsets.UTF_8);
    private final boolean suspendOnResponse;
    final AtomicReference<TrafficCop> trafficCop = new AtomicReference<>();
    final CountDownLatch responseReceived = new CountDownLatch(1);
    final CountDownLatch chunkReceived = new CountDownLatch(1);

    ResponseHandler(final boolean suspendOnResponse)
    {
      this.suspendOnResponse = suspendOnResponse;
    }

    @Override
    public ClientResponse<StringFullResponseHolder> handleResponse(final HttpResponse response, final TrafficCop cop)
    {
      trafficCop.set(cop);
      final ClientResponse<StringFullResponseHolder> result = delegate.handleResponse(response, cop);
      responseReceived.countDown();
      return new ClientResponse<>(result.isFinished(), !suspendOnResponse, result.getObj());
    }

    @Override
    public ClientResponse<StringFullResponseHolder> handleChunk(
        final ClientResponse<StringFullResponseHolder> response,
        final HttpChunk chunk,
        final long chunkNum
    )
    {
      final ClientResponse<StringFullResponseHolder> result = delegate.handleChunk(response, chunk, chunkNum);
      chunkReceived.countDown();
      return new ClientResponse<>(result.isFinished(), true, result.getObj());
    }

    @Override
    public ClientResponse<StringFullResponseHolder> done(final ClientResponse<StringFullResponseHolder> response)
    {
      return delegate.done(response);
    }

    @Override
    public void exceptionCaught(final ClientResponse<StringFullResponseHolder> response, final Throwable error)
    {
      delegate.exceptionCaught(response, error);
    }
  }

  private static class Fixture implements AutoCloseable
  {
    final SingleConnectionServer server = new SingleConnectionServer();
    private final Lifecycle lifecycle = new Lifecycle();
    final HttpClient client;
    final Request request;

    Fixture(final ResourcePool.Implementation implementation) throws Exception
    {
      client = HttpClientInit.createClient(
          HttpClientConfig.builder()
                          .withNumConnections(1)
                          .withWorkerCount(1)
                          .withPoolImplementation(implementation)
                          .build(),
          lifecycle
      );
      lifecycle.start();
      request = new Request(
          HttpMethod.GET,
          new URI("http://localhost:" + server.listener.getLocalPort() + "/").toURL()
      );
    }

    Channel returnedChannel()
    {
      final ResourceContainer<ChannelFuture> resource = ((NettyHttpClient) client).getPool().take(
          "http://localhost:" + server.listener.getLocalPort()
      );
      try {
        return resource.get().getChannel();
      }
      finally {
        resource.returnResource();
      }
    }

    @Override
    public void close() throws IOException
    {
      try {
        lifecycle.stop();
      }
      finally {
        server.close();
      }
    }
  }

  /**
   * Accepts exactly one connection: a subsequent request succeeds only if the client reuses that connection.
   */
  private static class SingleConnectionServer implements AutoCloseable
  {
    private final ServerSocket listener = new ServerSocket(0);
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final BlockingQueue<Reply> replies = new LinkedBlockingQueue<>();
    private final AtomicReference<Socket> connection = new AtomicReference<>();

    SingleConnectionServer() throws IOException
    {
      executor.submit(() -> {
        try (final Socket socket = listener.accept()) {
          connection.set(socket);
          final BufferedReader input =
              new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
          final OutputStream output = socket.getOutputStream();
          String line;
          while ((line = input.readLine()) != null) {
            if (line.isEmpty()) {
              Reply reply;
              do {
                reply = replies.take();
                output.write(StringUtils.toUtf8(reply.body()));
                output.flush();
              } while (!reply.complete());
            }
          }
        }
        catch (IOException e) {
          // The client may abort the response, or the fixture may close the connection.
        }
        catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      });
    }

    void send(final String body, final boolean complete)
    {
      replies.add(new Reply(body, complete));
    }

    @Override
    public void close() throws IOException
    {
      executor.shutdownNow();
      try {
        listener.close();
      }
      finally {
        final Socket socket = connection.get();
        if (socket != null) {
          socket.close();
        }
      }
    }
  }

  private record Reply(String body, boolean complete)
  {
  }
}
