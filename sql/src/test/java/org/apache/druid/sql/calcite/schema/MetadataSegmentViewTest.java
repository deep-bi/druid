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


package org.apache.druid.sql.calcite.schema;

import com.google.common.util.concurrent.Futures;
import org.apache.druid.client.BrokerSegmentWatcherConfig;
import org.apache.druid.client.coordinator.CoordinatorClient;
import org.apache.druid.collections.ResourceHolder;
import org.apache.druid.java.util.common.ISE;
import org.apache.druid.timeline.SegmentStatusInCluster;
import org.apache.druid.utils.CloseableUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class MetadataSegmentViewTest
{
  private MetadataSegmentView segmentView;
  private CoordinatorClient coordinatorClient;

  @BeforeEach
  public void setup()
  {
    coordinatorClient = Mockito.mock(CoordinatorClient.class);
    segmentView = new MetadataSegmentView(
        coordinatorClient,
        new BrokerSegmentWatcherConfig(),
        new BrokerSegmentMetadataCacheConfig()
        {
          @Override
          public boolean isMetadataSegmentCacheEnable()
          {
            return true;
          }

          @Override
          public long getMetadataSegmentPollPeriod()
          {
            return 100;
          }
        }
    );
  }

  @Test
  public void test_poll_releasesTheCoordinatorResponse() throws Exception
  {
    final CountDownLatch closed = new CountDownLatch(1);

    Mockito.when(
        coordinatorClient.fetchAllUsedSegmentsWithOvershadowedStatus(
            ArgumentMatchers.eq(null),
            ArgumentMatchers.eq(true)
        )
    ).thenAnswer(
        invocation -> Futures.immediateFuture(
            holder(List.<SegmentStatusInCluster>of().iterator(), closed::countDown)
        )
    );

    segmentView.start();
    try {
      Assertions.assertTrue(closed.await(30, TimeUnit.SECONDS), "poll must close the streamed response");
    }
    finally {
      segmentView.stop();
    }
  }

  @Test
  public void test_poll_releasesTheCoordinatorResponse_whenIterationFails() throws Exception
  {
    final CountDownLatch closed = new CountDownLatch(1);

    final Iterator<SegmentStatusInCluster> failsMidStream = new Iterator<>()
    {
      @Override
      public boolean hasNext()
      {
        throw new ISE("Coordinator response ended mid-stream");
      }

      @Override
      public SegmentStatusInCluster next()
      {
        throw new NoSuchElementException();
      }
    };

    Mockito.when(
        coordinatorClient.fetchAllUsedSegmentsWithOvershadowedStatus(
            ArgumentMatchers.eq(null),
            ArgumentMatchers.eq(true)
        )
    ).thenAnswer(
        invocation -> Futures.immediateFuture(holder(failsMidStream, closed::countDown))
    );

    segmentView.start();

    try {
      Assertions.assertTrue(
          closed.await(30, TimeUnit.SECONDS),
          "a failed poll must still release the streamed response"
      );
    }
    finally {
      segmentView.stop();
    }
  }

  @Test
  public void test_getSegments_releasesTheCoordinatorResponse_ifCacheIsDisabled() throws IOException
  {
    final AtomicBoolean closed = new AtomicBoolean(false);

    Mockito.when(
        coordinatorClient.fetchAllUsedSegmentsWithOvershadowedStatus(
            ArgumentMatchers.eq(null),
            ArgumentMatchers.eq(true)
        )
    ).thenReturn(
        Futures.immediateFuture(
            holder(List.<SegmentStatusInCluster>of().iterator(), () -> closed.set(true))
        )
    );

    final MetadataSegmentView uncachedView = new MetadataSegmentView(
        coordinatorClient,
        new BrokerSegmentWatcherConfig(),
        new BrokerSegmentMetadataCacheConfig()
        {
          @Override
          public boolean isMetadataSegmentCacheEnable()
          {
            return false;
          }
        }
    );

    uncachedView.getSegments().close();

    Assertions.assertTrue(closed.get());
  }

  private static ResourceHolder<Iterator<SegmentStatusInCluster>> holder(
      final Iterator<SegmentStatusInCluster> segments,
      final Closeable response
  )
  {
    return new ResourceHolder<>()
    {
      @Override
      public Iterator<SegmentStatusInCluster> get()
      {
        return segments;
      }

      @Override
      public void close()
      {
        CloseableUtils.closeAndWrapExceptions(response);
      }
    };
  }
}
