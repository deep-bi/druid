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

package org.apache.druid.indexing.kafka;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.druid.data.input.impl.InputRowParser;
import org.apache.druid.data.input.kafka.KafkaRecordEntity;
import org.apache.druid.data.input.kafka.KafkaTopicPartition;
import org.apache.druid.indexing.common.LockGranularity;
import org.apache.druid.indexing.common.TaskToolbox;
import org.apache.druid.indexing.seekablestream.SeekableStreamDataSourceMetadata;
import org.apache.druid.indexing.seekablestream.SeekableStreamEndSequenceNumbers;
import org.apache.druid.indexing.seekablestream.SeekableStreamIndexTaskRunner;
import org.apache.druid.indexing.seekablestream.SeekableStreamSequenceNumbers;
import org.apache.druid.indexing.seekablestream.SequenceMetadata;
import org.apache.druid.indexing.seekablestream.common.OrderedPartitionableRecord;
import org.apache.druid.indexing.seekablestream.common.OrderedSequenceNumber;
import org.apache.druid.indexing.seekablestream.common.RecordSupplier;
import org.apache.druid.indexing.seekablestream.common.StreamPartition;
import org.apache.druid.java.util.common.ISE;
import org.apache.druid.java.util.emitter.EmittingLogger;
import org.apache.druid.utils.CollectionUtils;
import org.apache.kafka.clients.consumer.OffsetOutOfRangeException;
import org.apache.kafka.common.TopicPartition;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

/**
 * Kafka indexing task runner that supports incremental segment publishing.
 */
public class KafkaIndexTaskRunner extends SeekableStreamIndexTaskRunner<KafkaTopicPartition, Long, KafkaRecordEntity>
{
  private static final EmittingLogger log = new EmittingLogger(KafkaIndexTaskRunner.class);
  private final KafkaIndexTask task;

  KafkaIndexTaskRunner(
      KafkaIndexTask task,
      @Nullable InputRowParser<ByteBuffer> parser,
      LockGranularity lockGranularityToUse
  )
  {
    super(
        task,
        parser,
        lockGranularityToUse
    );
    this.task = task;
  }

  @Override
  protected Long getNextStartOffset(@NotNull Long sequenceNumber)
  {
    return sequenceNumber + 1;
  }

  @Nonnull
  @Override
  protected List<OrderedPartitionableRecord<KafkaTopicPartition, Long, KafkaRecordEntity>> getRecords(
      RecordSupplier<KafkaTopicPartition, Long, KafkaRecordEntity> recordSupplier,
      TaskToolbox toolbox
  ) throws Exception
  {
    try {
      return recordSupplier.poll(task.getIOConfig().getPollTimeout());
    }
    catch (OffsetOutOfRangeException e) {
      //
      // Handles OffsetOutOfRangeException, which is thrown if the seeked-to
      // offset is not present in the topic-partition. This can happen if we're asking a task to read from data
      // that has not been written yet (which is totally legitimate). So let's wait for it to show up
      //
      log.warn("OffsetOutOfRangeException with message [%s]", e.getMessage());
      possiblyResetOffsetsOrWait(e.offsetOutOfRangePartitions(), recordSupplier, toolbox);
      return Collections.emptyList();
    }
  }

  @Override
  protected SeekableStreamEndSequenceNumbers<KafkaTopicPartition, Long> deserializePartitionsFromMetadata(
      ObjectMapper mapper,
      Object object
  )
  {
    return mapper.convertValue(object, mapper.getTypeFactory().constructParametrizedType(
        SeekableStreamEndSequenceNumbers.class,
        SeekableStreamEndSequenceNumbers.class,
        KafkaTopicPartition.class,
        Long.class
    ));
  }

  private void possiblyResetOffsetsOrWait(
      Map<TopicPartition, Long> outOfRangePartitions,
      RecordSupplier<KafkaTopicPartition, Long, KafkaRecordEntity> recordSupplier,
      TaskToolbox taskToolbox
  ) throws InterruptedException, IOException
  {
    final String stream = task.getIOConfig().getStartSequenceNumbers().getStream();
    final boolean isMultiTopic = task.getIOConfig().isMultiTopic();
    final Map<TopicPartition, Long> resetPartitions = new HashMap<>();
    boolean doReset = false;
    if (task.getTuningConfig().isResetOffsetAutomatically()) {
      for (Map.Entry<TopicPartition, Long> outOfRangePartition : outOfRangePartitions.entrySet()) {
        final TopicPartition topicPartition = outOfRangePartition.getKey();
        final long nextOffset = outOfRangePartition.getValue();
        // seek to the beginning to get the least available offset
        StreamPartition<KafkaTopicPartition> streamPartition = StreamPartition.of(
            stream,
            new KafkaTopicPartition(isMultiTopic, topicPartition.topic(), topicPartition.partition())
        );
        final Long leastAvailableOffset = recordSupplier.getEarliestSequenceNumber(streamPartition);
        if (leastAvailableOffset == null) {
          throw new ISE(
              "got null sequence number for partition[%s] when fetching from kafka!",
              topicPartition.partition()
          );
        }
        // reset the seek
        recordSupplier.seek(streamPartition, nextOffset);
        // Reset consumer offset if resetOffsetAutomatically is set to true
        // and the current message offset in the kafka partition is more than the
        // next message offset that we are trying to fetch
        if (leastAvailableOffset > nextOffset) {
          doReset = true;
          resetPartitions.put(topicPartition, nextOffset);
        }
      }
    }

    if (doReset) {
      sendResetRequestAndWait(CollectionUtils.mapKeys(resetPartitions, topicPartition -> StreamPartition.of(
          stream,
          new KafkaTopicPartition(isMultiTopic, topicPartition.topic(), topicPartition.partition())
      )), taskToolbox);
    } else {
      log.warn("Retrying in %dms", task.getPollRetryMs());
      pollRetryLock.lockInterruptibly();
      try {
        long nanos = TimeUnit.MILLISECONDS.toNanos(task.getPollRetryMs());
        while (nanos > 0L && !pauseRequested && !stopRequested.get()) {
          nanos = isAwaitingRetry.awaitNanos(nanos);
        }
      }
      finally {
        pollRetryLock.unlock();
      }
    }
  }

  @Override
  protected SeekableStreamDataSourceMetadata<KafkaTopicPartition, Long> createDataSourceMetadata(
      SeekableStreamSequenceNumbers<KafkaTopicPartition, Long> partitions
  )
  {
    return new KafkaDataSourceMetadata(partitions);
  }

  @Override
  protected OrderedSequenceNumber<Long> createSequenceNumber(Long sequenceNumber)
  {
    return KafkaSequenceNumber.of(sequenceNumber);
  }

  @Override
  protected void possiblyResetDataSourceMetadata(
      TaskToolbox toolbox,
      RecordSupplier<KafkaTopicPartition, Long, KafkaRecordEntity> recordSupplier,
      Set<StreamPartition<KafkaTopicPartition>> assignment
  )
  {
    // do nothing
  }

  @Override
  protected boolean isEndOffsetExclusive()
  {
    return true;
  }

  @Override
  protected boolean isEndOfShard(Long seqNum)
  {
    return false;
  }

  @Override
  public TypeReference<List<SequenceMetadata<KafkaTopicPartition, Long>>> getSequenceMetadataTypeReference()
  {
    return new TypeReference<>() {};
  }

  @Nullable
  @Override
  protected TreeMap<Integer, Map<KafkaTopicPartition, Long>> getCheckPointsFromContext(
      TaskToolbox toolbox,
      String checkpointsString
  ) throws IOException
  {
    if (checkpointsString != null) {
      log.debug("Got checkpoints from task context[%s].", checkpointsString);
      return toolbox.getJsonMapper().readValue(
          checkpointsString,
          new TypeReference<>() {}
      );
    } else {
      return null;
    }
  }
}

