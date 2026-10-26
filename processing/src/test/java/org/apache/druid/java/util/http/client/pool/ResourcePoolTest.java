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
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.apache.druid.java.util.common.ISE;
import org.apache.druid.java.util.common.concurrent.Execs;
import org.apache.druid.testing.junit.LoggerCaptureRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.annotation.Nullable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * The contract every {@link ResourcePool.Implementation} owes its callers, followed by the promises each
 * implementation makes on its own.
 */
public class ResourcePoolTest
{
  private static final long NEVER_EXPIRES = TimeUnit.MINUTES.toMillis(5);
  private static final long EXPIRES_QUICKLY = 100;

  public final LoggerCaptureRule logger = new LoggerCaptureRule(ResourcePool.class);

  private TestResourceFactory factory;

  @BeforeEach
  public void setUp()
  {
    factory = new TestResourceFactory();
    logger.before();
  }

  @AfterEach
  public void tearDown()
  {
    logger.after();
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testReturnedResourceIsReused(ResourcePool.Implementation implementation)
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, NEVER_EXPIRES, false);

    final ResourceContainer<String> first = pool.take("billy");
    Assertions.assertEquals("billy#0", first.get());
    first.returnResource();

    final ResourceContainer<String> second = pool.take("billy");
    Assertions.assertEquals("billy#0", second.get(), "a returned resource is handed out again");
    second.returnResource();

    Assertions.assertEquals(List.of("billy#0"), factory.opened(), "no second connection is opened");
    Assertions.assertEquals(List.of(), factory.closed());
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testEagerInitializationFillsAKeyOnItsFirstTake(ResourcePool.Implementation implementation)
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, NEVER_EXPIRES, true);
    Assertions.assertEquals(List.of(), factory.opened(), "an untouched key costs nothing");

    final ResourceContainer<String> billy = pool.take("billy");
    Assertions.assertEquals(List.of("billy#0", "billy#1"), factory.opened());
    Assertions.assertEquals("billy#0", billy.get());
    billy.returnResource();
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testTakeBlocksWhileEveryResourceIsLent(ResourcePool.Implementation implementation) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, NEVER_EXPIRES, false);

    final ResourceContainer<String> first = pool.take("billy");
    final ResourceContainer<String> second = pool.take("billy");

    final BackgroundTake third = BackgroundTake.start(pool, "billy");
    Assertions.assertTrue(third.isBlocked(), "a third take while both resources are lent");

    first.returnResource();
    Assertions.assertEquals("billy#0", third.awaitResource(), "the returned resource unblocks the waiting take");
    third.release();
    second.returnResource();

    Assertions.assertEquals(2, factory.opened().size(), "the pool never opens more than maxPerKey");
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testUnhealthyResourceIsClosedAndReplaced(ResourcePool.Implementation implementation)
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, NEVER_EXPIRES, false);
    pool.take("billy").returnResource();

    factory.markUnhealthy("billy#0");

    final ResourceContainer<String> replacement = pool.take("billy");
    Assertions.assertEquals("billy#1", replacement.get());
    Assertions.assertEquals(List.of("billy#0"), factory.closed());
    replacement.returnResource();
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testExpiredResourceIsDiscardedWithoutTouchingOtherKeys(ResourcePool.Implementation implementation)
      throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, EXPIRES_QUICKLY, false);
    pool.take("billy").returnResource();
    awaitExpiry();
    pool.take("sally").returnResource();

    final ResourceContainer<String> billy = pool.take("billy");
    Assertions.assertEquals("billy#1", billy.get(), "the expired resource must not be handed out");
    billy.returnResource();

    final ResourceContainer<String> sally = pool.take("sally");
    Assertions.assertEquals("sally#0", sally.get(), "expiry of one key must not touch another key");
    sally.returnResource();

    Assertions.assertEquals(List.of("billy#0"), factory.closed());
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testCloseDiscardsIdleResourcesAndRefusesFurtherTakes(ResourcePool.Implementation implementation)
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, NEVER_EXPIRES, false);
    pool.take("billy").returnResource();

    pool.close();

    Assertions.assertEquals(List.of("billy#0"), factory.closed());
    Assertions.assertNull(pool.take("billy"), "take after close");
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testCloseUnblocksAWaitingTake(ResourcePool.Implementation implementation) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, NEVER_EXPIRES, false);
    final ResourceContainer<String> lent = pool.take("billy");

    final BackgroundTake waiter = BackgroundTake.start(pool, "billy");
    Assertions.assertTrue(waiter.isBlocked(), "a take while the only resource is lent");

    pool.close();
    Assertions.assertNull(waiter.awaitResource(), "a take unblocked by close() hands out nothing");
    waiter.release();

    lent.returnResource();
    Assertions.assertEquals(List.of("billy#0"), factory.closed(), "a resource returned after close is closed");
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testReturningTwiceRepaysOneSlotOnly(ResourcePool.Implementation implementation) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, NEVER_EXPIRES, false);
    final ResourceContainer<String> billy = pool.take("billy");
    billy.returnResource();
    billy.returnResource();

    Assertions.assertThrows(IllegalStateException.class, billy::get, "a returned container cannot be read again");

    final ResourceContainer<String> reused = pool.take("billy");
    final BackgroundTake extra = BackgroundTake.start(pool, "billy");
    Assertions.assertTrue(extra.isBlocked(), "the second return must not have created a second slot");

    reused.returnResource();
    Assertions.assertEquals("billy#0", extra.awaitResource());
    extra.release();
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testFailedGenerateDoesNotConsumeASlot(ResourcePool.Implementation implementation) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, NEVER_EXPIRES, false);
    factory.failGenerate(new ISE("no more billies"));

    Assertions.assertThrows(ISE.class, () -> pool.take("billy"));

    factory.healGenerate();
    final BackgroundTake next = BackgroundTake.start(pool, "billy");
    Assertions.assertEquals("billy#0", next.awaitResource(), "the failed take must give its slot back");
    next.release();
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testFailedHealthCheckDoesNotConsumeASlot(ResourcePool.Implementation implementation) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, NEVER_EXPIRES, false);
    pool.take("billy").returnResource();
    factory.failHealthCheck("billy#0", new ISE("health check blew up"));

    Assertions.assertThrows(ISE.class, () -> pool.take("billy"));

    final BackgroundTake next = BackgroundTake.start(pool, "billy");
    Assertions.assertEquals("billy#1", next.awaitResource(), "the failed take must give its slot back");
    next.release();
  }

  /**
   * Under contention, with expiry constantly evicting resources, the pool never lends one resource to two callers,
   * never exceeds maxPerKey, never hands out a closed resource and never loses one.
   */
  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testConcurrentTakersNeverShareAResource(ResourcePool.Implementation implementation) throws Exception
  {
    final int maxPerKey = 4;
    final int takers = 8;
    final ResourcePool<String, String> pool = createPool(implementation, maxPerKey, 5, false);

    final Set<String> lent = ConcurrentHashMap.newKeySet();
    final AtomicInteger lentCount = new AtomicInteger();
    final AtomicReference<String> misuse = new AtomicReference<>();

    final ExecutorService exec = Execs.multiThreaded(takers, "resource-pool-stress-%d");
    final List<Future<?>> futures = new ArrayList<>();
    for (int i = 0; i < takers; i++) {
      futures.add(exec.submit(() -> {
        for (int j = 0; j < 200; j++) {
          final ResourceContainer<String> container = pool.take("billy");
          final String resource = container.get();
          if (!lent.add(resource)) {
            misuse.compareAndSet(null, "lent to two takers at once: " + resource);
          }
          if (lentCount.incrementAndGet() > maxPerKey) {
            misuse.compareAndSet(null, "more than " + maxPerKey + " lent at once");
          }
          if (factory.isClosed(resource)) {
            misuse.compareAndSet(null, "lent after being closed: " + resource);
          }
          lentCount.decrementAndGet();
          lent.remove(resource);
          container.returnResource();
        }
      }));
    }
    for (final Future<?> future : futures) {
      future.get(30, TimeUnit.SECONDS);
    }
    exec.shutdown();
    pool.close();

    Assertions.assertNull(misuse.get());
    Assertions.assertEquals(Set.copyOf(factory.opened()), Set.copyOf(factory.closed()), "every resource is closed");
    Assertions.assertEquals(factory.opened().size(), factory.closed().size(), "no resource is closed twice");
  }

  /**
   * One take() discards every expired resource it walks past and opens a single replacement, so a pool that ran hot
   * shrinks back to what the traffic needs instead of re-handshaking up to maxPerKey one take at a time.
   */
  @Test
  public void testAdaptivePurgesEveryExpiredResourceInOneTake() throws Exception
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 3, EXPIRES_QUICKLY, true);
    pool.take("billy").returnResource();
    awaitExpiry();

    final ResourceContainer<String> fresh = pool.take("billy");
    Assertions.assertEquals("billy#3", fresh.get());
    fresh.returnResource();

    Assertions.assertEquals(Set.of("billy#0", "billy#1", "billy#2"), Set.copyOf(factory.closed()));
    Assertions.assertEquals(4, factory.opened().size(), "exactly one replacement is opened");
  }

  /**
   * A peer restart kills every pooled resource at once, long before any of them expires. One take() must clear them
   * all rather than discovering them one take - and one handshake on a caller's thread - at a time.
   */
  @Test
  public void testAdaptivePurgesEveryDeadResourceInOneTake()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 3, NEVER_EXPIRES, true);
    pool.take("billy").returnResource();
    factory.markUnhealthy("billy#0", "billy#1", "billy#2");

    final ResourceContainer<String> fresh = pool.take("billy");
    Assertions.assertEquals("billy#3", fresh.get());
    fresh.returnResource();

    Assertions.assertEquals(Set.of("billy#0", "billy#1", "billy#2"), Set.copyOf(factory.closed()));
  }

  /**
   * A resource that broke while it was lent out is closed on its way back instead of being parked for the next
   * taker, whose health check would only discover it a moment later.
   */
  @Test
  public void testAdaptiveDiscardsABrokenResourceOnGiveBack()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 1, NEVER_EXPIRES, false);
    final ResourceContainer<String> lent = pool.take("billy");
    factory.markUnhealthy("billy#0");

    lent.returnResource();
    Assertions.assertEquals(List.of("billy#0"), factory.closed());

    final ResourceContainer<String> fresh = pool.take("billy");
    Assertions.assertEquals("billy#1", fresh.get(), "the discarded resource repaid its slot");
    fresh.returnResource();
  }

  /**
   * A freshly opened resource that fails its health check is handed over rather than replaced: opening another
   * connection cannot mend a peer that is refusing health checks, so the caller gets its resource and a warning is
   * logged.
   */
  @Test
  public void testAdaptiveHandsOverAFreshResourceThatFailsItsHealthCheck()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 2, NEVER_EXPIRES, false);
    factory.markUnhealthy("billy#0");

    final ResourceContainer<String> lent = pool.take("billy");
    Assertions.assertEquals("billy#0", lent.get(), "no replacement is opened");
    Assertions.assertEquals(List.of("billy#0"), factory.opened(), "and none is attempted either");
    Assertions.assertEquals(List.of(), factory.closed(), "the handed over resource stays open");
    Assertions.assertTrue(
        logger.getLogEvents().stream().anyMatch(e -> e.getMessage().getFormattedMessage().contains("billy#0")),
        "the caller is warned about it"
    );

    lent.returnResource();
    Assertions.assertTrue(factory.isClosed("billy#0"), "and it is discarded once it comes back");
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testStatsRecordWhatHappenedToTheResourcesOfAKey(ResourcePool.Implementation implementation)
      throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, EXPIRES_QUICKLY, false);
    pool.take("billy").returnResource();
    awaitExpiry();
    pool.take("billy").returnResource();
    pool.take("sally").returnResource();

    final Map<String, ResourcePool.Stats> stats = pool.drainStats();
    Assertions.assertEquals(Set.of("billy", "sally"), stats.keySet(), "one entry per key");

    final ResourcePool.Stats billy = stats.get("billy");
    Assertions.assertEquals(2, billy.opened(), "opened");
    Assertions.assertEquals(1, billy.closed(), "closed");
    Assertions.assertEquals(1, billy.timedOut(), "timed out");
    Assertions.assertEquals(0, billy.errored(), "errored");
    Assertions.assertEquals(2, billy.taken(), "taken");
    Assertions.assertEquals(2, billy.returned(), "returned");
    Assertions.assertEquals(0, billy.used(), "nothing is lent out");
    Assertions.assertEquals(1, billy.idle(), "the returned resource waits for the next caller");

    Assertions.assertEquals(1, stats.get("sally").opened(), "keys are counted apart");
  }

  /**
   * The counted events are drained as they are read, so an idle key reports zeroes rather than the totals it
   * reported before, while what it holds keeps being reported.
   */
  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testDrainedStatsCoverOnlyWhatHappenedSinceThePreviousDrain(ResourcePool.Implementation implementation)
  {
    final ResourcePool<String, String> pool = createPool(implementation, 2, NEVER_EXPIRES, false);
    final ResourceContainer<String> lent = pool.take("billy");
    pool.drainStats();

    final ResourcePool.Stats idle = pool.drainStats().get("billy");
    Assertions.assertEquals(0, idle.opened(), "opened");
    Assertions.assertEquals(0, idle.taken(), "taken");
    Assertions.assertEquals(1, idle.used(), "the lent resource is still out");
    Assertions.assertEquals(0, idle.idle(), "and is not parked");

    lent.returnResource();
    final ResourcePool.Stats afterReturn = pool.drainStats().get("billy");
    Assertions.assertEquals(1, afterReturn.returned(), "returned");
    Assertions.assertEquals(0, afterReturn.used(), "used");
    Assertions.assertEquals(1, afterReturn.idle(), "idle");
  }

  @Test
  public void testStatsRecordAFailingHealthCheckAsAnError()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 2, NEVER_EXPIRES, false);
    pool.take("billy").returnResource();
    factory.failHealthCheck("billy#0", new ISE("health check blew up"));

    Assertions.assertThrows(ISE.class, () -> pool.take("billy"));

    final ResourcePool.Stats stats = pool.drainStats().get("billy");
    Assertions.assertEquals(1, stats.errored(), "errored");
    Assertions.assertEquals(1, stats.closed(), "the resource whose check threw is closed");
  }

  /**
   * A resource taken off the queue and handed to nobody is closed rather than leaked.
   */
  @Test
  public void testAdaptiveClosesTheResourceWhoseHealthCheckThrows()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 2, NEVER_EXPIRES, false);
    pool.take("billy").returnResource();
    factory.failHealthCheck("billy#0", new ISE("health check blew up"));

    Assertions.assertThrows(ISE.class, () -> pool.take("billy"));
    Assertions.assertEquals(List.of("billy#0"), factory.closed());
  }

  /**
   * A resource that fails to close while being evicted does not fail the take that evicted it, and does not strand
   * the resources queued behind it.
   */
  @Test
  public void testAdaptiveSurvivesAFailingClose() throws Exception
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 2, EXPIRES_QUICKLY, true);
    pool.take("billy").returnResource();
    awaitExpiry();
    // billy#1 is at the head of the queue, so it is the first one evicted.
    factory.failClose("billy#1", new ISE("close blew up"));

    final ResourceContainer<String> fresh = pool.take("billy");
    Assertions.assertEquals("billy#2", fresh.get());
    fresh.returnResource();

    Assertions.assertEquals(Set.of("billy#0", "billy#1"), Set.copyOf(factory.closed()));
  }

  /**
   * Resources opened before a failing eager initialization are closed - the half-built holder never reaches the
   * cache, so nothing can ever reach them again.
   */
  @Test
  public void testAdaptiveClosesResourcesOpenedBeforeAFailedEagerInitialization()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 3, NEVER_EXPIRES, true);
    factory.failGenerateAfter(2, new ISE("no more billies"));

    final Exception thrown = Assertions.assertThrows(UncheckedExecutionException.class, () -> pool.take("billy"));
    Assertions.assertEquals("no more billies", thrown.getCause().getMessage());
    Assertions.assertEquals(List.of("billy#0", "billy#1"), factory.closed());
  }

  /**
   * A null from {@link ResourceFactory#generate} fails the take instead of producing a container that blows up on
   * {@link ResourceContainer#returnResource} and never repays its lent slot.
   */
  @Test
  public void testAdaptiveRejectsANullResource()
  {
    final ResourcePool<String, String> pool = createPool(ResourcePool.Implementation.ADAPTIVE, 2, NEVER_EXPIRES, false);
    factory.generateNull();

    Assertions.assertThrows(NullPointerException.class, () -> pool.take("billy"));
  }

  /**
   * The retaining pool keeps its high-water mark: an expired resource is replaced one for one, and the resources
   * queued behind it stay parked until their own turn comes.
   */
  @Test
  public void testRetainingReplacesAnExpiredResourceOneForOne() throws Exception
  {
    final ResourcePool<String, String> pool =
        createPool(ResourcePool.Implementation.RETAINING, 2, EXPIRES_QUICKLY, true);
    pool.take("billy").returnResource();
    awaitExpiry();

    final ResourceContainer<String> fresh = pool.take("billy");
    Assertions.assertEquals("billy#2", fresh.get());
    fresh.returnResource();

    Assertions.assertEquals(List.of("billy#1"), factory.closed(), "only the resource at the head is discarded");
    Assertions.assertEquals(3, factory.opened().size(), "the expired resource is replaced one for one");
  }

  @Test
  public void testAbandonmentTimeoutDefaultsAndOverflow()
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

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testAbandonedEndpointIsClosedAndRemoved(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 3, true, ticker)) {
      pool.take("old").returnResource();
      ticker.advance(10, TimeUnit.SECONDS);
      pool.take("new").returnResource();
      Assertions.assertEquals(Set.of("old#0", "old#1", "old#2"), Set.copyOf(factory.closed()));
      Assertions.assertFalse(pool.drainStats().containsKey("old"));
      Assertions.assertEquals(Set.of("new"), pool.drainStats().keySet());
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testReturnStartsANewAbandonmentInterval(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, false, ticker)) {
      final ResourceContainer<String> loan = pool.take("old");
      ticker.advance(30, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertEquals(List.of(), factory.closed());
      loan.returnResource();
      ticker.advance(9, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertTrue(pool.drainStats().containsKey("old"));
      ticker.advance(1, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertFalse(pool.drainStats().containsKey("old"));
      Assertions.assertEquals(List.of("old#0"), factory.closed());
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testBorrowReservationPreventsConcurrentRetirement(ResourcePool.Implementation implementation)
      throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch checking = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, true, ticker)) {
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
        Assertions.assertTrue(pool.drainStats().containsKey("old"));
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

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testCreationReservationPreventsConcurrentRetirement(ResourcePool.Implementation implementation)
      throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch creating = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, false, ticker)) {
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
        // Reading retaining gauges takes its monitor, which creation currently holds.
        Assertions.assertEquals(List.of(), factory.closed());
      }
      finally {
        proceed.countDown();
      }
      Assertions.assertEquals("old#0", borrow.awaitResource());
      borrow.release();
      Assertions.assertTrue(pool.drainStats().containsKey("old"));
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testRetirementFinishesBeforeReplacementIsCreated(ResourcePool.Implementation implementation)
      throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch closing = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    final ExecutorService exec = Execs.multiThreaded(2, "retirement-race-%d");
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, true, ticker)) {
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

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testFailedCleanupIsRetriedWithoutSkippingOtherResources(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 3, true, ticker)) {
      pool.take("old").returnResource();
      pool.take("another").returnResource();
      factory.failClose("old#1", new ISE("injected close failure"));
      ticker.advance(10, TimeUnit.SECONDS);
      pool.take("new").returnResource();
      final Map<String, ResourcePool.Stats> stats = pool.drainStats();
      Assertions.assertFalse(stats.containsKey("another"));
      Assertions.assertTrue(stats.containsKey("old"), "failed cleanup stays reachable for retry");
      Assertions.assertEquals(2, stats.get("old").closed());
      Assertions.assertEquals(1, stats.get("old").errored());
      Assertions.assertTrue(factory.closed().containsAll(List.of("old#0", "old#2", "another#0", "another#1", "another#2")));
      factory.closeFaults.remove("old#1");
      ticker.advance(1, TimeUnit.SECONDS);
      pool.take("new").returnResource();
      Assertions.assertFalse(pool.drainStats().containsKey("old"));
      Assertions.assertEquals(2, Collections.frequency(factory.closed(), "old#1"));
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testFailedCleanupDoesNotCreateAnotherPoolForTheSameKey(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, true, ticker)) {
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

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testCleanupPropagatesErrorsAndCanResume(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, true, ticker)) {
      pool.take("old").returnResource();
      factory.closeErrors.put("old#0", new AssertionError("injected fatal error"));
      ticker.advance(10, TimeUnit.SECONDS);
      Assertions.assertThrows(AssertionError.class, () -> pool.take("other"));
      factory.closeErrors.clear();
      ticker.advance(1, TimeUnit.SECONDS);
      pool.take("other").returnResource();
      Assertions.assertFalse(pool.drainStats().containsKey("old"));
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testMetricsDoNotPerformCleanup(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 1, true, ticker)) {
      pool.take("old").returnResource();
      ticker.advance(20, TimeUnit.SECONDS);
      Assertions.assertTrue(pool.drainStats().containsKey("old"));
      Assertions.assertEquals(List.of(), factory.closed());
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testShutdownRetriesFailedClosesAndClosesUnsweptEntries(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    final ResourcePool<String, String> pool = timedPool(implementation, 2, true, ticker);
    pool.take("old").returnResource();
    factory.failClose("old#1", new ISE("injected close failure"));
    ticker.advance(20, TimeUnit.SECONDS);
    pool.close();
    Assertions.assertEquals(Set.of("old#0", "old#1"), Set.copyOf(factory.closed()));
    Assertions.assertTrue(pool.drainStats().containsKey("old"));
    factory.closeFaults.clear();
    pool.close();
    Assertions.assertTrue(pool.drainStats().isEmpty());
    Assertions.assertEquals(1, Collections.frequency(factory.closed(), "old#0"));
    Assertions.assertEquals(2, Collections.frequency(factory.closed(), "old#1"));
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testConcurrentEagerCreationAndShutdownCannotOrphanAHolder(ResourcePool.Implementation implementation)
      throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final CountDownLatch creating = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    final ExecutorService exec = Execs.multiThreaded(2, "shutdown-race-%d");
    final ResourcePool<String, String> pool = timedPool(implementation, 1, true, ticker);
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
      Assertions.assertTrue(pool.drainStats().isEmpty());
    }
    finally {
      proceed.countDown();
      exec.shutdownNow();
      pool.close();
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testEndpointChurnKeepsOnlyTheRecentIdleWindow(ResourcePool.Implementation implementation)
  {
    final FakeTicker ticker = new FakeTicker();
    try (final ResourcePool<String, String> pool = timedPool(implementation, 2, true, ticker)) {
      for (int i = 0; i < 100; i++) {
        ticker.advance(1, TimeUnit.SECONDS);
        pool.take("endpoint-" + i).returnResource();
        Assertions.assertTrue(pool.drainStats().size() <= 10, "old endpoint entries are removed");
        Assertions.assertTrue(factory.opened().size() - factory.closed().size() <= 20, "connections track the idle window");
      }
    }
    Assertions.assertEquals(Set.copyOf(factory.opened()), Set.copyOf(factory.closed()));
    Assertions.assertEquals(factory.opened().size(), factory.closed().size());
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testLoanCanBeReturnedOnAnotherThreadAfterShutdown(ResourcePool.Implementation implementation)
      throws Exception
  {
    final FakeTicker ticker = new FakeTicker();
    final ResourcePool<String, String> pool = timedPool(implementation, 1, false, ticker);
    final ResourceContainer<String> loan = pool.take("old");
    final ExecutorService exec = Execs.singleThreaded("cross-thread-return");
    try {
      pool.close();
      Assertions.assertEquals(List.of(), factory.closed());
      exec.submit(loan::returnResource).get(5, TimeUnit.SECONDS);
      Assertions.assertEquals(List.of("old#0"), factory.closed());
      Assertions.assertTrue(pool.drainStats().isEmpty());
    }
    finally {
      exec.shutdownNow();
      pool.close();
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testLastWaitingAcquisitionRemovesClosedDestinationAfterShutdown(
      final ResourcePool.Implementation implementation
  ) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, NEVER_EXPIRES, false);
    final ResourceContainer<String> loan = pool.take("old");
    final Object lifecycle = lifecycleLock(pool, "old");
    final BackgroundTake waiter = BackgroundTake.start(pool, "old");
    boolean returned = false;
    try {
      awaitWaiting(waiter.thread);
      // Delay the waiter's final reservation release until shutdown and the loan return have finished.
      synchronized (lifecycle) {
        pool.close();
        loan.returnResource();
        returned = true;
        Assertions.assertTrue(pool.drainStats().containsKey("old"), "the waiter still holds a reservation");
      }
      Assertions.assertNull(waiter.awaitResource());
      waiter.release();
      Assertions.assertEquals(List.of("old#0"), factory.closed());
      Assertions.assertTrue(pool.drainStats().isEmpty(), "the final acquisition must remove the closed destination");
    }
    finally {
      pool.close();
      if (!returned) {
        loan.returnResource();
      }
      waiter.release();
      pool.close();
    }
  }

  @ParameterizedTest
  @EnumSource(ResourcePool.Implementation.class)
  public void testFailedAcquisitionRemovesClosedDestinationAfterShutdown(
      final ResourcePool.Implementation implementation
  ) throws Exception
  {
    final ResourcePool<String, String> pool = createPool(implementation, 1, NEVER_EXPIRES, false);
    pool.take("old").returnResource();
    final ExecutorService exec = Execs.singleThreaded("failed-acquisition-after-shutdown");
    final CountDownLatch checking = new CountDownLatch(1);
    final CountDownLatch proceed = new CountDownLatch(1);
    final ISE failure = new ISE("Replacement failed after shutdown");
    factory.markUnhealthy("old#0");
    factory.beforeHealthCheck = resource -> {
      checking.countDown();
      awaitSignal(proceed);
    };
    try {
      final Future<ResourceContainer<String>> acquisition = exec.submit(() -> pool.take("old"));
      awaitSignal(checking);
      factory.failGenerate(failure);
      pool.close();
      Assertions.assertTrue(pool.drainStats().containsKey("old"), "the pending acquisition still holds a reservation");
      proceed.countDown();
      final ExecutionException exception = Assertions.assertThrows(
          ExecutionException.class,
          () -> acquisition.get(5, TimeUnit.SECONDS)
      );
      Assertions.assertSame(failure, exception.getCause(), "cleanup must preserve the acquisition failure");
      Assertions.assertEquals(factory.opened(), factory.closed());
      Assertions.assertTrue(pool.drainStats().isEmpty(), "the failed acquisition must remove the closed destination");
    }
    finally {
      proceed.countDown();
      exec.shutdownNow();
      Assertions.assertTrue(exec.awaitTermination(5, TimeUnit.SECONDS));
      pool.close();
    }
  }

  private static Object lifecycleLock(final ResourcePool<?, ?> pool, final Object key)
      throws ReflectiveOperationException
  {
    final Field cacheField = ResourcePool.class.getDeclaredField("pool");
    cacheField.setAccessible(true);
    final LoadingCache<?, ?> cache = (LoadingCache<?, ?>) cacheField.get(pool);
    final Object holder = cache.getIfPresent(key);
    Assertions.assertNotNull(holder);
    final Class<?> holderClass = Class.forName(ResourcePool.class.getName() + "$PooledResources");
    final Field lifecycleField = holderClass.getDeclaredField("lifecycle");
    lifecycleField.setAccessible(true);
    return lifecycleField.get(holder);
  }

  private static void awaitWaiting(final Thread thread) throws InterruptedException
  {
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (thread.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
      Thread.sleep(1);
    }
    Assertions.assertEquals(Thread.State.WAITING, thread.getState(), "the acquisition must be waiting for a resource");
  }

  private ResourcePool<String, String> timedPool(
      final ResourcePool.Implementation implementation,
      final int maxPerKey,
      final boolean eager,
      final FakeTicker ticker
  )
  {
    return new ResourcePool<>(factory, new ResourcePoolConfig(maxPerKey, 1000, implementation), eager, ticker);
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

  private ResourcePool<String, String> createPool(
      ResourcePool.Implementation implementation,
      int maxPerKey,
      long unusedResourceTimeoutMillis,
      boolean eagerInitialization
  )
  {
    return new ResourcePool<>(
        factory,
        new ResourcePoolConfig(maxPerKey, unusedResourceTimeoutMillis, implementation),
        eagerInitialization
    );
  }

  /**
   * Waits until every idle resource of an {@link #EXPIRES_QUICKLY} pool has gone stale.
   */
  private static void awaitExpiry() throws InterruptedException
  {
    Thread.sleep(EXPIRES_QUICKLY * 3);
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

    static BackgroundTake start(ResourcePool<String, String> pool, String key)
    {
      return new BackgroundTake(pool, key);
    }

    private BackgroundTake(ResourcePool<String, String> pool, String key)
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

    boolean isBlocked() throws InterruptedException
    {
      return !taken.await(200, TimeUnit.MILLISECONDS);
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

  /**
   * Hands out resources named {@code key#n} and records what the pool did with them. Faults are injected per
   * resource, so a test names the resource it wants broken rather than scripting a sequence of calls.
   */
  private static class TestResourceFactory implements ResourceFactory<String, String>
  {
    private final ConcurrentMap<String, AtomicInteger> sequences = new ConcurrentHashMap<>();
    private final List<String> opened = Collections.synchronizedList(new ArrayList<>());
    private final List<String> closed = Collections.synchronizedList(new ArrayList<>());
    private final Set<String> unhealthy = ConcurrentHashMap.newKeySet();
    private final ConcurrentMap<String, RuntimeException> healthCheckFaults = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, RuntimeException> closeFaults = new ConcurrentHashMap<>();
    private final AtomicInteger generatesBeforeFault = new AtomicInteger();

    private final ConcurrentMap<String, Error> closeErrors = new ConcurrentHashMap<>();
    private volatile Consumer<String> beforeGenerate = key -> {};
    private volatile Consumer<String> beforeHealthCheck = resource -> {};
    private volatile Consumer<String> beforeClose = resource -> {};
    private volatile RuntimeException generateFault;
    private volatile boolean generateNull;

    @Override
    public String generate(String key)
    {
      beforeGenerate.accept(key);
      if (generateFault != null && generatesBeforeFault.getAndDecrement() <= 0) {
        throw generateFault;
      }
      if (generateNull) {
        return null;
      }
      final String resource = key + "#" + sequences.computeIfAbsent(key, k -> new AtomicInteger()).getAndIncrement();
      opened.add(resource);
      return resource;
    }

    @Override
    public boolean isGood(String resource)
    {
      beforeHealthCheck.accept(resource);
      final RuntimeException fault = healthCheckFaults.get(resource);
      if (fault != null) {
        throw fault;
      }
      return !unhealthy.contains(resource);
    }

    @Override
    public void close(String resource)
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

    /**
     * Every resource ever opened, in the order they were opened.
     */
    List<String> opened()
    {
      return List.copyOf(opened);
    }

    /**
     * Every close, in the order they happened - a resource closed twice appears twice.
     */
    List<String> closed()
    {
      return List.copyOf(closed);
    }

    boolean isClosed(String resource)
    {
      return closed.contains(resource);
    }

    void markUnhealthy(String... resources)
    {
      unhealthy.addAll(List.of(resources));
    }

    void failHealthCheck(String resource, RuntimeException fault)
    {
      healthCheckFaults.put(resource, fault);
    }

    void failClose(String resource, RuntimeException fault)
    {
      closeFaults.put(resource, fault);
    }

    void failGenerate(RuntimeException fault)
    {
      failGenerateAfter(0, fault);
    }

    void failGenerateAfter(int successfulGenerates, RuntimeException fault)
    {
      generatesBeforeFault.set(successfulGenerates);
      generateFault = fault;
    }

    void healGenerate()
    {
      generateFault = null;
    }

    void generateNull()
    {
      generateNull = true;
    }
  }
}
