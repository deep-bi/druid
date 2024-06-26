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

package org.apache.druid.indexing.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.Inject;
import org.apache.druid.guice.annotations.Json;
import org.apache.druid.segment.IndexIO;
import org.apache.druid.segment.loading.LeastBytesUsedStorageLocationSelectorStrategy;
import org.apache.druid.segment.loading.SegmentCacheManager;
import org.apache.druid.segment.loading.SegmentLoaderConfig;
import org.apache.druid.segment.loading.SegmentLocalCacheManager;
import org.apache.druid.segment.loading.StorageLocation;
import org.apache.druid.segment.loading.StorageLocationConfig;

import java.io.File;
import java.util.Collections;
import java.util.List;

/**
 *
 */
public class SegmentCacheManagerFactory
{
  private final IndexIO indexIO;
  private final ObjectMapper jsonMapper;

  @Inject
  public SegmentCacheManagerFactory(
      IndexIO indexIO,
      @Json ObjectMapper mapper
  )
  {
    this.indexIO = indexIO;
    this.jsonMapper = mapper;
  }

  public SegmentCacheManager manufacturate(File storageDir)
  {
    final SegmentLoaderConfig loaderConfig = new SegmentLoaderConfig().withLocations(
        Collections.singletonList(new StorageLocationConfig(storageDir, null, null))
    );
    final List<StorageLocation> storageLocations = loaderConfig.toStorageLocations();
    return new SegmentLocalCacheManager(
        storageLocations,
        loaderConfig,
        new LeastBytesUsedStorageLocationSelectorStrategy(storageLocations),
        indexIO,
        jsonMapper
    );
  }
}
