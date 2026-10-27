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

import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.google.common.base.Throwables;
import com.google.common.base.Ticker;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.common.logger.Logger;

import javax.annotation.Nullable;
import java.io.Closeable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongSupplier;

/**
 * Lends at most {@link ResourcePoolConfig#getMaxPerKey()} resources per destination.
 * Idle resources are replaced on access after {@link ResourcePoolConfig#getUnusedConnectionTimeoutMillis()}.
 * Abandoned destinations are retired during later takes, without evicting borrowed or pending resources.
 */
public class ResourcePool<K, V> implements Closeable
{
  private static final Logger log = new Logger(ResourcePool.class);
  private final LoadingCache<K, PooledResources<V>> pool;
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final ReentrantReadWriteLock cacheLifecycle = new ReentrantReadWriteLock();
  private final AtomicBoolean sweeping = new AtomicBoolean(false);
  private final LongSupplier clock;
  private final long abandonmentTimeoutMillis;
  private final long sweepIntervalMillis;
  private volatile long nextSweepMillis;

  public ResourcePool(final ResourceFactory<K, V> factory, final ResourcePoolConfig config,
                      final boolean eagerInitialization)
  {
    this(factory, config, eagerInitialization, Ticker.systemTicker());
  }

  ResourcePool(
      final ResourceFactory<K, V> factory,
      final ResourcePoolConfig config,
      final boolean eagerInitialization,
      final Ticker ticker
  )
  {
    final Stopwatch stopwatch = Stopwatch.createStarted(ticker);
    this.clock = () -> stopwatch.elapsed(TimeUnit.MILLISECONDS);
    this.abandonmentTimeoutMillis = config.getAbandonedKeyTimeoutMillis();
    this.sweepIntervalMillis = config.getMaintenanceIntervalMillis();
    this.nextSweepMillis = sweepIntervalMillis;
    this.pool = CacheBuilder.newBuilder().build(
        new CacheLoader<>()
        {
          @Override
          public PooledResources<V> load(final K input)
          {
            if (eagerInitialization) {
              return new EagerCreationResourceHolder<>(
                  config.getMaxPerKey(),
                  config.getUnusedConnectionTimeoutMillis(),
                  input,
                  factory,
                  clock
              );
            }
            return new LazyCreationResourceHolder<>(
                config.getMaxPerKey(),
                config.getUnusedConnectionTimeoutMillis(),
                input,
                factory,
                clock
            );
          }
        }
    );
  }

  /**
   * Returns a {@link ResourceContainer} for the given key or null if this pool is already closed.
   */
  @Nullable
  public ResourceContainer<V> take(final K key)
  {
    reapAbandonedKeys();
    while (!closed.get()) {
      final PooledResources<V> holder;
      cacheLifecycle.readLock().lock();
      try {
        if (closed.get()) {
          return null;
        }
        holder = pool.get(key);
      }
      catch (ExecutionException e) {
        throw new RuntimeException(e);
      }
      finally {
        cacheLifecycle.readLock().unlock();
      }

      final V value = holder.get();
      if (value == null) {
        if (closed.get() || Thread.currentThread().isInterrupted() || !holder.isRetired()) {
          return null;
        }
        closeAndRemove(key, holder);
        Preconditions.checkState(holder.isFullyClosed(), "Cleanup is pending for retired pool at key[%s]", key);
        continue;
      }
      if (closed.get()) {
        holder.giveBack(value);
        closeAndRemove(key, holder);
        return null;
      }

      return new ResourceContainer<>()
      {
        private final AtomicBoolean returned = new AtomicBoolean(false);

        @Override
        public V get()
        {
          Preconditions.checkState(!returned.get(), "Resource for key[%s] has been returned, cannot get().", key);
          return value;
        }

        @Override
        public void returnResource()
        {
          if (returned.getAndSet(true)) {
            log.warn("Resource at key[%s] was returned multiple times?", key);
          } else {
            holder.giveBack(value);
            if (closed.get()) {
              closeAndRemove(key, holder);
            }
          }
        }

        @Override
        protected void finalize() throws Throwable
        {
          if (!returned.get()) {
            log.warn(
                StringUtils.format(
                    "Resource[%s] at key[%s] was not returned before Container was finalized, potential resource leak.",
                    value,
                    key
                )
            );
            returnResource();
          }
          super.finalize();
        }
      };
    }
    return null;
  }

  private void reapAbandonedKeys()
  {
    final long now = clock.getAsLong();
    if (now < nextSweepMillis || !sweeping.compareAndSet(false, true)) {
      return;
    }
    try {
      if (now < nextSweepMillis) {
        return;
      }
      nextSweepMillis = now > Long.MAX_VALUE - sweepIntervalMillis ? Long.MAX_VALUE : now + sweepIntervalMillis;
      for (final Map.Entry<K, PooledResources<V>> entry : pool.asMap().entrySet()) {
        final PooledResources<V> holder = entry.getValue();
        if (holder.tryRetireIfIdle(now, abandonmentTimeoutMillis)) {
          closeAndRemove(entry.getKey(), holder);
        }
      }
    }
    finally {
      sweeping.set(false);
    }
  }

  private void closeAndRemove(final K key, final PooledResources<V> holder)
  {
    holder.close();
    if (holder.isFullyClosed()) {
      pool.asMap().remove(key, holder);
    }
  }

  @Override
  public void close()
  {
    final ArrayList<Map.Entry<K, PooledResources<V>>> entries;
    cacheLifecycle.writeLock().lock();
    try {
      closed.set(true);
      entries = new ArrayList<>(pool.asMap().entrySet());
    }
    finally {
      cacheLifecycle.writeLock().unlock();
    }
    for (final Map.Entry<K, PooledResources<V>> entry : entries) {
      closeAndRemove(entry.getKey(), entry.getValue());
    }
  }

  private abstract static class PooledResources<V> implements Closeable
  {
    private final Object lifecycle = new Object();
    private final Object cleanup = new Object();
    private final LongSupplier clock;
    private final Object destination;
    private final Deque<Runnable> failedCloses = new ConcurrentLinkedDeque<>();
    private long lastActivityMillis;
    private int reservations;
    private boolean retired;

    PooledResources(final Object destination, final LongSupplier clock)
    {
      this.destination = destination;
      this.clock = clock;
      lastActivityMillis = clock.getAsLong();
    }

    // A reservation covers waiting, creation, borrowing, and return, even across different threads.
    @Nullable
    final V get()
    {
      synchronized (lifecycle) {
        if (retired) {
          return null;
        }
        reservations++;
      }
      boolean lent = false;
      try {
        final V value = borrow();
        lent = value != null;
        return value;
      }
      finally {
        if (!lent) {
          releaseReservation();
        }
      }
    }

    final void giveBack(final V value)
    {
      try {
        returnToPool(value);
      }
      finally {
        releaseReservation();
      }
    }

    private void releaseReservation()
    {
      synchronized (lifecycle) {
        reservations--;
        lastActivityMillis = clock.getAsLong();
      }
    }

    final boolean tryRetireIfIdle(final long now, final long timeoutMillis)
    {
      synchronized (lifecycle) {
        if (!retired && (reservations != 0 || now - lastActivityMillis < timeoutMillis)) {
          return false;
        }
        retired = true;
        return true;
      }
    }

    final boolean isRetired()
    {
      synchronized (lifecycle) {
        return retired;
      }
    }

    final boolean isFullyClosed()
    {
      synchronized (cleanup) {
        synchronized (lifecycle) {
          return retired && reservations == 0 && failedCloses.isEmpty() && getIdleCount() == 0;
        }
      }
    }

    final void closeResource(final Runnable action)
    {
      boolean succeeded = false;
      try {
        action.run();
        succeeded = true;
      }
      catch (RuntimeException e) {
        log.warn(e, "Failed to close a pooled resource at key[%s]; retaining it for retry", destination);
      }
      finally {
        if (!succeeded) {
          failedCloses.addLast(action);
        }
      }
    }

    @Override
    public final void close()
    {
      synchronized (lifecycle) {
        retired = true;
      }
      synchronized (cleanup) {
        // Retry each failed resource once per pass, without preventing other resources from closing.
        final int pending = failedCloses.size();
        for (int i = 0; i < pending; i++) {
          final Runnable action = failedCloses.pollFirst();
          if (action != null) {
            closeResource(action);
          }
        }
        closeResources();
      }
    }

    @Nullable
    abstract V borrow();

    abstract void returnToPool(V object);

    abstract int getIdleCount();

    abstract void closeResources();
  }

  private static class EagerCreationResourceHolder<K, V> extends LazyCreationResourceHolder<K, V>
  {
    private EagerCreationResourceHolder(
        final int maxSize,
        final long unusedResourceTimeoutMillis,
        final K key,
        final ResourceFactory<K, V> factory,
        final LongSupplier clock
    )
    {
      super(maxSize, unusedResourceTimeoutMillis, key, factory, clock);
      // Eagerly Instantiate
      for (int i = 0; i < maxSize; i++) {
        resourceHolderList.add(
            new ResourceHolder<>(
                System.currentTimeMillis(),
                Preconditions.checkNotNull(
                    this.factory.generate(key),
                    "factory.generate(key)"
                )
            )
        );
      }
    }
  }

  private static class LazyCreationResourceHolder<K, V> extends ResourceHolderPerKey<K, V>
  {
    private LazyCreationResourceHolder(
        final int maxSize,
        final long unusedResourceTimeoutMillis,
        final K key,
        final ResourceFactory<K, V> factory,
        final LongSupplier clock
    )
    {
      super(maxSize, unusedResourceTimeoutMillis, key, factory, clock);
    }
  }

  private static class ResourceHolderPerKey<K, V> extends PooledResources<V>
  {
    protected final int maxSize;
    protected final ResourceFactory<K, V> factory;
    private final K key;
    private final long unusedResourceTimeoutMillis;
    // Hold previously created / returned resources
    protected final ArrayDeque<ResourceHolder<V>> resourceHolderList;
    // To keep track of resources that have been successfully returned to caller.
    private int numLentResources = 0;
    private boolean closed = false;

    protected ResourceHolderPerKey(
        final int maxSize,
        final long unusedResourceTimeoutMillis,
        final K key,
        final ResourceFactory<K, V> factory,
        final LongSupplier clock
    )
    {
      super(key, clock);
      this.maxSize = maxSize;
      this.key = key;
      this.factory = factory;
      this.unusedResourceTimeoutMillis = unusedResourceTimeoutMillis;
      this.resourceHolderList = new ArrayDeque<>();
    }

    /**
     * Returns a resource or null if this holder is already closed or the current thread is interrupted.
     *
     * Try to return a previously created resource if it isGood(). Else, generate a new resource
     */
    @Nullable
    @Override
    V borrow()
    {
      final V poolVal;
      // resourceHolderList can't have nulls, so we'll use a null to signal that we need to create a new resource.
      boolean expired = false;
      synchronized (this) {
        while (!closed && (numLentResources == maxSize)) {
          try {
            this.wait();
          }
          catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
          }
        }

        if (closed) {
          log.info(StringUtils.format("get() called even though I'm closed. key[%s]", key));
          return null;
        } else if (numLentResources < maxSize) {
          // Attempt to take an existing resource or create one if list is empty, and increment numLentResources
          if (resourceHolderList.isEmpty()) {
            poolVal = factory.generate(key);
          } else {
            final ResourceHolder<V> holder = resourceHolderList.removeFirst();
            poolVal = holder.getResource();
            if (System.currentTimeMillis() - holder.getLastAccessedTime() > unusedResourceTimeoutMillis) {
              expired = true;
            }
          }
          numLentResources++;
        } else {
          throw new IllegalStateException("Unexpected state: More objects lent than permissible");
        }
      }

      final V retVal;
      // At this point, we must either return a valid resource. Or throw and exception decrement "numLentResources"
      try {
        if (poolVal != null && !expired && factory.isGood(poolVal)) {
          retVal = poolVal;
        } else {
          if (poolVal != null) {
            factory.close(poolVal);
          }
          retVal = factory.generate(key);
        }
      }
      catch (Throwable e) {
        synchronized (this) {
          numLentResources--;
          this.notifyAll();
        }
        Throwables.propagateIfPossible(e);
        throw new RuntimeException(e);
      }

      return retVal;
    }

    @Override
    void returnToPool(final V object)
    {
      Preconditions.checkNotNull(object, "object");

      synchronized (this) {
        if (closed) {
          log.info(StringUtils.format("giveBack called after being closed. key[%s]", key));
          closeResource(() -> factory.close(object));
          numLentResources--;
          this.notifyAll();
          return;
        }

        if (resourceHolderList.size() >= maxSize) {
          if (holderListContains(object)) {
            log.warn(
                new Exception("Exception for stacktrace"),
                StringUtils.format(
                    "Returning object[%s] at key[%s] that has already been returned!? Skipping",
                    object,
                    key
                )
            );
          } else {
            log.warn(
                new Exception("Exception for stacktrace"),
                StringUtils.format(
                    "Returning object[%s] at key[%s] even though we already have all that we can hold[%s]!? Skipping",
                    object,
                    key,
                    resourceHolderList
                )
            );
          }
          return;
        }

        resourceHolderList.addLast(new ResourceHolder<>(System.currentTimeMillis(), object));
        numLentResources--;
        this.notifyAll();
      }
    }

    @Override
    synchronized int getIdleCount()
    {
      return resourceHolderList.size();
    }

    private boolean holderListContains(final V object)
    {
      return resourceHolderList.stream().anyMatch(a -> a.getResource().equals(object));
    }

    @Override
    void closeResources()
    {
      synchronized (this) {
        closed = true;
        try {
          for (ResourceHolder<V> holder = resourceHolderList.pollFirst(); holder != null;
               holder = resourceHolderList.pollFirst()) {
            final V resource = holder.getResource();
            closeResource(() -> factory.close(resource));
          }
        }
        finally {
          this.notifyAll();
        }
      }
    }
  }

  private static class ResourceHolder<V>
  {
    private final long lastAccessedTime;
    private final V resource;

    private ResourceHolder(long lastAccessedTime, V resource)
    {
      this.resource = resource;
      this.lastAccessedTime = lastAccessedTime;
    }

    private long getLastAccessedTime()
    {
      return lastAccessedTime;
    }

    public V getResource()
    {
      return resource;
    }

  }
}
