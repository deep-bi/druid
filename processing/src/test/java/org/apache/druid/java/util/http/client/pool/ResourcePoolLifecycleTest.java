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

package org.apache.druid.java.util.http.client.pool;

import com.google.common.cache.LoadingCache;
import com.google.common.testing.FakeTicker;
import org.apache.druid.java.util.common.ISE;
import org.apache.druid.java.util.common.concurrent.Execs;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.annotation.Nullable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Abandoned-destination lifecycle regressions backported from PR #41 for the Druid 37 retaining pool.
 */
public class ResourcePoolLifecycleTest
{
  private TestResourceFactory factory;

  @BeforeEach
  public void setUp()
  {
    factory = new TestResourceFactory();
  }

  @Test
  public void testAbandonmentTimeoutDefaultsAndOverflow() throws Exception
  {
    final ResourcePoolConfig normal = new ResourcePoolConfig(1, TimeUnit.MINUTES.toMillis(4));
    Assertions.assertEquals(TimeUnit.MINUTES.toMillis(40), normal.getAbandonedKeyTimeoutMillis());
    for (final long timeout : new long[]{0, -1}) {
      final ResourcePoolConfig fallback = new ResourcePoolConfig(1, timeout);
      Assertions.assertEquals(TimeUnit.MINUTES.toMillis(1), fallback.getMaintenanceIntervalMillis());
      Assertions.assertEquals(TimeUnit.MINUTES.toMillis(10), fallback.getAbandonedKeyTimeoutMillis());
    }
    Assertions.assertEquals(Long.MAX_VALUE, new ResourcePoolConfig(1, Long.MAX_VALUE).getAbandonedKeyTimeoutMillis());
  }

  @Test
  public void testAbandonedEndpointIsClosedAndRemoved() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(3, true, ticker)) {
      pool.take("old").returnResource();
      ticker.advance(10, TimeUnit.SECONDS);
      pool.take("new").returnResource();
      Assertions.assertEquals(Set.of("old#0", "old#1", "old#2"), Set.copyOf(factory.closed()));
      Assertions.assertFalse(cachedKeys(pool).contains("old"));
      Assertions.assertEquals(Set.of("new"), cachedKeys(pool));
    }
  }

  @Test
  public void testReturnStartsANewAbandonmentInterval() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(1, false, ticker)) {
      final ResourceContainer<String> loan = pool.take("old");
      ticker.advance(30, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertEquals(List.of(), factory.closed());
      loan.returnResource();
      ticker.advance(9, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertTrue(cachedKeys(pool).contains("old"));
      ticker.advance(1, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertFalse(cachedKeys(pool).contains("old"));
      Assertions.assertEquals(List.of("old#0"), factory.closed());
    }
  }

  @Test
  public void testBorrowReservationPreventsConcurrentRetirement() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch checking = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    try (final ResourcePool<String, String> pool = timedPool(1, true, ticker)) {
      pool.take("old").returnResource();
      ticker.advance(9, TimeUnit.SECONDS);
      factory.beforeHealthCheck = resource -> {
        if ("old#0".equals(resource)) {
          checking.countDown();
          awaitSignal(proceed);
        }
      };
      final BackgroundTake borrow = BackgroundTake.start(pool, "old");
      try {
        awaitSignal(checking);
        ticker.advance(2, TimeUnit.SECONDS);
        pool.take("other").returnResource();
        Assertions.assertTrue(cachedKeys(pool).contains("old"));
        Assertions.assertEquals(List.of(), factory.closed());
      }
      finally {
        proceed.countDown();
      }
      Assertions.assertEquals("old#0", borrow.awaitResource());
      borrow.release();
      Assertions.assertEquals(List.of("old#0", "other#0"), factory.opened());
    }
  }

  @Test
  public void testCreationReservationPreventsConcurrentRetirement() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch creating = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    try (final ResourcePool<String, String> pool = timedPool(1, false, ticker)) {
      factory.beforeGenerate = key -> {
        if ("old".equals(key)) {
          creating.countDown();
          awaitSignal(proceed);
        }
      };
      final BackgroundTake borrow = BackgroundTake.start(pool, "old");
      try {
        awaitSignal(creating);
        ticker.advance(20, TimeUnit.SECONDS);
        pool.take("other").returnResource();
        Assertions.assertEquals(List.of(), factory.closed());
      }
      finally {
        proceed.countDown();
      }
      Assertions.assertEquals("old#0", borrow.awaitResource());
      borrow.release();
      Assertions.assertTrue(cachedKeys(pool).contains("old"));
    }
  }

  @Test
  public void testRetirementFinishesBeforeReplacementIsCreated() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch closing = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    final ExecutorService exec = Execs.multiThreaded(2, "retirement-race-%d");
    try (final ResourcePool<String, String> pool = timedPool(1, true, ticker)) {
      pool.take("old").returnResource();
      ticker.advance(10, TimeUnit.SECONDS);
      factory.beforeClose = resource -> {
        if ("old#0".equals(resource)) {
          closing.countDown();
          awaitSignal(proceed);
        }
      };
      final Future<?> sweep = exec.submit(() -> pool.take("other").returnResource());
      awaitSignal(closing);
      final Future<ResourceContainer<String>> replacement = exec.submit(() -> pool.take("old"));
      try {
        Assertions.assertThrows(TimeoutException.class, () -> replacement.get(100, TimeUnit.MILLISECONDS));
        Assertions.assertEquals(List.of("old#0"), factory.opened());
      }
      finally {
        proceed.countDown();
      }
      sweep.get(5, TimeUnit.SECONDS);
      final ResourceContainer<String> loan = replacement.get(5, TimeUnit.SECONDS);
      Assertions.assertEquals("old#1", loan.get());
      loan.returnResource();
    }
    finally {
      proceed.countDown();
      exec.shutdownNow();
    }
  }

  @Test
  public void testFailedCleanupIsRetriedWithoutSkippingOtherResources() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(3, true, ticker)) {
      pool.take("old").returnResource();
      pool.take("another").returnResource();
      factory.failClose("old#1", new ISE("injected close failure"));
      ticker.advance(10, TimeUnit.SECONDS);
      pool.take("new").returnResource();
      final Set<?> keys = cachedKeys(pool);
      Assertions.assertFalse(keys.contains("another"));
      Assertions.assertTrue(keys.contains("old"), "failed cleanup stays reachable for retry");
      Assertions.assertTrue(factory.closed().containsAll(List.of("old#0", "old#2", "another#0", "another#1", "another#2")));
      factory.closeFaults.remove("old#1");
      ticker.advance(1, TimeUnit.SECONDS);
      pool.take("new").returnResource();
      Assertions.assertFalse(cachedKeys(pool).contains("old"));
      Assertions.assertEquals(2, Collections.frequency(factory.closed(), "old#1"));
    }
  }

  @Test
  public void testFailedCleanupDoesNotCreateAnotherPoolForTheSameKey() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(1, true, ticker)) {
      pool.take("old").returnResource();
      factory.failClose("old#0", new ISE("injected close failure"));
      ticker.advance(10, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertThrows(IllegalStateException.class, () -> pool.take("old"));
      Assertions.assertEquals(List.of("old#0", "other#0"), factory.opened());
      factory.closeFaults.clear();
      final ResourceContainer<String> replacement = pool.take("old");
      Assertions.assertEquals("old#1", replacement.get());
      replacement.returnResource();
    }
  }

  @Test
  public void testCleanupPropagatesErrorsAndCanResume() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(1, true, ticker)) {
      pool.take("old").returnResource();
      factory.closeErrors.put("old#0", new AssertionError("injected fatal error"));
      ticker.advance(10, TimeUnit.SECONDS);
      Assertions.assertThrows(AssertionError.class, () -> pool.take("other"));
      factory.closeErrors.clear();
      ticker.advance(1, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertFalse(cachedKeys(pool).contains("old"));
    }
  }

  @Test
  public void testShutdownRetriesFailedClosesAndClosesUnsweptEntries() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final ResourcePool<String, String> pool = timedPool(2, true, ticker);
    pool.take("old").returnResource();
    factory.failClose("old#1", new ISE("injected close failure"));
    ticker.advance(20, TimeUnit.SECONDS);
    pool.close();
    Assertions.assertEquals(Set.of("old#0", "old#1"), Set.copyOf(factory.closed()));
    Assertions.assertTrue(cachedKeys(pool).contains("old"));
    factory.closeFaults.clear();
    pool.close();
    Assertions.assertTrue(cachedKeys(pool).isEmpty());
    Assertions.assertEquals(1, Collections.frequency(factory.closed(), "old#0"));
    Assertions.assertEquals(2, Collections.frequency(factory.closed(), "old#1"));
  }

  @Test
  public void testConcurrentEagerCreationAndShutdownCannotOrphanAHolder() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch creating = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    final ExecutorService exec = Execs.multiThreaded(2, "shutdown-race-%d");
    final ResourcePool<String, String> pool = timedPool(1, true, ticker);
    factory.beforeGenerate = key -> {
      creating.countDown();
      awaitSignal(proceed);
    };
    try {
      final Future<ResourceContainer<String>> take = exec.submit(() -> pool.take("old"));
      awaitSignal(creating);
      final Future<?> close = exec.submit(pool::close);
      Assertions.assertThrows(TimeoutException.class, () -> close.get(100, TimeUnit.MILLISECONDS));
      proceed.countDown();
      final ResourceContainer<String> loan = take.get(5, TimeUnit.SECONDS);
      close.get(5, TimeUnit.SECONDS);
      if (loan != null) {
        loan.returnResource();
      }
      pool.close();
      Assertions.assertEquals(factory.opened(), factory.closed());
      Assertions.assertTrue(cachedKeys(pool).isEmpty());
    }
    finally {
      proceed.countDown();
      exec.shutdownNow();
      pool.close();
    }
  }

  @Test
  public void testEndpointChurnKeepsOnlyTheRecentIdleWindow() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(2, true, ticker)) {
      for (int i = 0; i < 100; i++) {
        ticker.advance(1, TimeUnit.SECONDS);
        pool.take("endpoint-" + i).returnResource();
        Assertions.assertTrue(cachedKeys(pool).size() <= 10, "old endpoint entries are removed");
        Assertions.assertTrue(factory.opened().size() - factory.closed().size() <= 20, "connections track the idle window");
      }
    }
    Assertions.assertEquals(Set.copyOf(factory.opened()), Set.copyOf(factory.closed()));
    Assertions.assertEquals(factory.opened().size(), factory.closed().size());
  }

  @Test
  public void testLoanCanBeReturnedOnAnotherThreadAfterShutdown() throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final ResourcePool<String, String> pool = timedPool(1, false, ticker);
    final ResourceContainer<String> loan = pool.take("old");
    final ExecutorService exec = Execs.singleThreaded("cross-thread-return");
    try {
      pool.close();
      Assertions.assertEquals(List.of(), factory.closed());
      exec.submit(loan::returnResource).get(5, TimeUnit.SECONDS);
      Assertions.assertEquals(List.of("old#0"), factory.closed());
      Assertions.assertTrue(cachedKeys(pool).isEmpty());
    }
    finally {
      exec.shutdownNow();
      pool.close();
    }
  }

  private ResourcePool<String, String> timedPool(
      final int maxPerKey,
      final boolean eager,
      final FakeTicker ticker
  )
  {
    return new ResourcePool<>(factory, new ResourcePoolConfig(maxPerKey, 1000), eager, ticker);
  }

  private static Set<?> cachedKeys(final ResourcePool<?, ?> pool) throws ReflectiveOperationException
  {
    final Field field = ResourcePool.class.getDeclaredField("pool");
    field.setAccessible(true);
    final LoadingCache<?, ?> cache = (LoadingCache<?, ?>) field.get(pool);
    return Set.copyOf(cache.asMap().keySet());
  }

  private static void awaitSignal(final CountDownLatch latch)
  {
    try {
      Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS), "test operation completed");
    }
    catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }
  }

  /**
   * A take() running on its own thread, so a test can watch it block and decide when it gives its resource back.
   */
  private static class BackgroundTake
  {
    private final CountDownLatch taken = new CountDownLatch(1);
    private final CountDownLatch released = new CountDownLatch(1);
    private final Thread thread;

    private volatile ResourceContainer<String> container;
    private volatile Throwable failure;

    static BackgroundTake start(final ResourcePool<String, String> pool, final String key)
    {
      return new BackgroundTake(pool, key);
    }

    private BackgroundTake(final ResourcePool<String, String> pool, final String key)
    {
      this.thread = new Thread(
          () -> {
            try {
              container = pool.take(key);
              taken.countDown();
              released.await();
              if (container != null) {
                container.returnResource();
              }
            }
            catch (Throwable t) {
              failure = t;
            }
            finally {
              taken.countDown();
            }
          },
          "background-take-" + key
      );
      thread.setDaemon(true);
      thread.start();
    }

    /**
     * The resource taken, or null if the pool handed out nothing. Fails if the take never completes - which is what
     * a leaked slot looks like, since the pool blocks once every slot is handed out.
     */
    @Nullable
    String awaitResource() throws InterruptedException
    {
      Assertions.assertTrue(taken.await(5, TimeUnit.SECONDS), "the take completed");
      return container == null ? null : container.get();
    }

    /**
     * Gives the resource back and asserts that neither taking nor returning threw.
     */
    void release() throws InterruptedException
    {
      released.countDown();
      thread.join(TimeUnit.SECONDS.toMillis(5));
      Assertions.assertNull(failure, "the background take failed");
    }
  }

  private static class TestResourceFactory implements ResourceFactory<String, String>
  {
    private final ConcurrentMap<String, AtomicInteger> sequences = new ConcurrentHashMap<>();
    private final List<String> opened = Collections.synchronizedList(new ArrayList<>());
    private final List<String> closed = Collections.synchronizedList(new ArrayList<>());
    private final ConcurrentMap<String, RuntimeException> closeFaults = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Error> closeErrors = new ConcurrentHashMap<>();
    private volatile Consumer<String> beforeGenerate = key -> {};
    private volatile Consumer<String> beforeHealthCheck = resource -> {};
    private volatile Consumer<String> beforeClose = resource -> {};

    @Override
    public String generate(final String key)
    {
      beforeGenerate.accept(key);
      final String resource = key + "#" + sequences.computeIfAbsent(key, k -> new AtomicInteger()).getAndIncrement();
      opened.add(resource);
      return resource;
    }

    @Override
    public boolean isGood(final String resource)
    {
      beforeHealthCheck.accept(resource);
      return true;
    }

    @Override
    public void close(final String resource)
    {
      closed.add(resource);
      beforeClose.accept(resource);
      final Error error = closeErrors.get(resource);
      if (error != null) {
        throw error;
      }
      final RuntimeException fault = closeFaults.get(resource);
      if (fault != null) {
        throw fault;
      }
    }

    List<String> opened()
    {
      return List.copyOf(opened);
    }

    List<String> closed()
    {
      return List.copyOf(closed);
    }

    void failClose(final String resource, final RuntimeException fault)
    {
      closeFaults.put(resource, fault);
    }
  }
}
