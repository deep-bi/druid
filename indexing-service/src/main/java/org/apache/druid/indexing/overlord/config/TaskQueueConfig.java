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

package org.apache.druid.indexing.overlord.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.druid.common.config.Configs;
import org.apache.druid.java.util.common.HumanReadableBytes;
import org.joda.time.Duration;
import org.joda.time.Period;

import javax.annotation.Nullable;

public class TaskQueueConfig
{
  @JsonProperty
  private int maxSize;

  @JsonProperty
  private Duration startDelay;

  @JsonProperty
  private Duration restartDelay;

  @JsonProperty
  private Duration storageSyncRate;

  @JsonProperty
  private int taskCompleteHandlerNumThreads;

  @JsonProperty
  private HumanReadableBytes maxTaskPayloadSize;

  @Nullable
  @JsonProperty
  private Float controllerTaskSlotRatio;

  @Nullable
  @JsonProperty
  private Integer maxControllerTaskSlots;

  @JsonCreator
  public TaskQueueConfig(
      @JsonProperty("maxSize") final Integer maxSize,
      @JsonProperty("startDelay") final Period startDelay,
      @JsonProperty("restartDelay") final Period restartDelay,
      @JsonProperty("storageSyncRate") final Period storageSyncRate,
      @JsonProperty("taskCompleteHandlerNumThreads") final Integer taskCompleteHandlerNumThreads,
      @JsonProperty("maxTaskPayloadSize") @Nullable final HumanReadableBytes maxTaskPayloadSize,
      @Nullable @JsonProperty("controllerTaskSlotRatio") final Float controllerTaskSlotRatio,
      @Nullable @JsonProperty("maxControllerTaskSlots") final Integer maxControllerTaskSlots
  )
  {
    this.maxSize = Configs.valueOrDefault(maxSize, Integer.MAX_VALUE);
    this.taskCompleteHandlerNumThreads = Configs.valueOrDefault(taskCompleteHandlerNumThreads, 5);
    this.startDelay = defaultDuration(startDelay, "PT1M");
    this.restartDelay = defaultDuration(restartDelay, "PT30S");
    this.storageSyncRate = defaultDuration(storageSyncRate, "PT1M");
    this.maxTaskPayloadSize = maxTaskPayloadSize;
    if (controllerTaskSlotRatio != null && maxControllerTaskSlots != null) {
      throw new IllegalArgumentException(
          "Only one controller task limit parameter should be specified, controllerTaskSlotRatio or maxControllerTaskSlots");
    } else if (controllerTaskSlotRatio != null && controllerTaskSlotRatio > 1 && controllerTaskSlotRatio <= 0) {
      throw new IllegalArgumentException(
          "controllerTaskSlotRatio is out of range (0;1]");
    }
    this.controllerTaskSlotRatio = controllerTaskSlotRatio;
    this.maxControllerTaskSlots = maxControllerTaskSlots;
  }

  public int getMaxSize()
  {
    return maxSize;
  }

  public int getTaskCompleteHandlerNumThreads()
  {
    return taskCompleteHandlerNumThreads;
  }

  public Duration getStartDelay()
  {
    return startDelay;
  }

  public Duration getRestartDelay()
  {
    return restartDelay;
  }

  public Duration getStorageSyncRate()
  {
    return storageSyncRate;
  }

  public HumanReadableBytes getMaxTaskPayloadSize()
  {
    return maxTaskPayloadSize;
  }

  private static Duration defaultDuration(final Period period, final String theDefault)
  {
    return (period == null ? new Period(theDefault) : period).toStandardDuration();
  }

  @Nullable
  public Integer getMaxControllerTaskSlots()
  {
    return maxControllerTaskSlots;
  }

  @Nullable
  public Float getControllerTaskSlotRatio()
  {
    return controllerTaskSlotRatio;
  }
}
