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

package org.apache.druid.rpc.indexing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.util.concurrent.ListenableFuture;
import org.apache.druid.client.indexing.ClientKillUnusedSegmentsTaskQuery;
import org.apache.druid.client.indexing.ClientTaskQuery;
import org.apache.druid.client.indexing.IndexingTotalWorkerCapacityInfo;
import org.apache.druid.client.indexing.IndexingWorker;
import org.apache.druid.client.indexing.IndexingWorkerInfo;
import org.apache.druid.client.indexing.TaskPayloadResponse;
import org.apache.druid.common.guava.FutureUtils;
import org.apache.druid.indexer.CompactionEngine;
import org.apache.druid.indexer.RunnerTaskState;
import org.apache.druid.indexer.TaskLocation;
import org.apache.druid.indexer.TaskState;
import org.apache.druid.indexer.TaskStatusPlus;
import org.apache.druid.indexer.report.KillTaskReport;
import org.apache.druid.indexer.report.TaskReport;
import org.apache.druid.indexing.overlord.supervisor.SupervisorSpec;
import org.apache.druid.indexing.overlord.supervisor.SupervisorStatus;
import org.apache.druid.jackson.DefaultObjectMapper;
import org.apache.druid.java.util.common.DateTimes;
import org.apache.druid.java.util.common.Intervals;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.http.client.response.StringFullResponseHolder;
import org.apache.druid.metadata.LockFilterPolicy;
import org.apache.druid.metadata.TestSupervisorSpec;
import org.apache.druid.rpc.HttpResponseException;
import org.apache.druid.rpc.MockServiceClient;
import org.apache.druid.rpc.RequestBuilder;
import org.apache.druid.rpc.UpdateResponse;
import org.apache.druid.segment.TestDataSource;
import org.apache.druid.server.compaction.NewestSegmentFirstPolicy;
import org.apache.druid.server.coordinator.ClusterCompactionConfig;
import org.apache.druid.server.http.SegmentsToUpdateFilter;
import org.apache.druid.timeline.DataSegment;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.joda.time.Interval;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class OverlordClientImplTest
{
  private static final List<TaskStatusPlus> STATUSES = Collections.singletonList(
      new TaskStatusPlus(
          "taskId",
          null,
          null,
          DateTimes.of("2000"),
          DateTimes.of("2000"),
          TaskState.RUNNING,
          RunnerTaskState.RUNNING,
          null,
          TaskLocation.unknown(),
          null,
          null
      )
  );

  private ObjectMapper jsonMapper;
  private MockServiceClient serviceClient;
  private OverlordClient overlordClient;

  @Before
  public void setup()
  {
    jsonMapper = new DefaultObjectMapper();
    serviceClient = new MockServiceClient();
    overlordClient = new OverlordClientImpl(serviceClient, jsonMapper);
  }

  @After
  public void tearDown()
  {
    serviceClient.verify();
  }

  @Test
  public void test_findCurrentLeader() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/leader"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        StringUtils.toUtf8("http://followTheLeader")
    );

    Assert.assertEquals(URI.create("http://followTheLeader"), overlordClient.findCurrentLeader().get());
  }

  @Test
  public void test_taskStatuses_null_null_null() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/tasks"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(STATUSES)
    );

    Assert.assertEquals(
        STATUSES,
        ImmutableList.copyOf(overlordClient.taskStatuses(null, null, null).get())
    );
  }

  @Test
  public void test_taskStatuses_RUNNING_null_null() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/tasks?state=RUNNING"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(STATUSES)
    );

    Assert.assertEquals(
        STATUSES,
        ImmutableList.copyOf(overlordClient.taskStatuses("RUNNING", null, null).get())
    );
  }

  @Test
  public void test_taskStatuses_RUNNING_foo_null() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/tasks?state=RUNNING&datasource=foo"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(STATUSES)
    );

    Assert.assertEquals(
        STATUSES,
        ImmutableList.copyOf(overlordClient.taskStatuses("RUNNING", "foo", null).get())
    );
  }

  @Test
  public void test_taskStatuses_null_foo_null() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/tasks?datasource=foo"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(STATUSES)
    );

    Assert.assertEquals(
        STATUSES,
        ImmutableList.copyOf(overlordClient.taskStatuses(null, "foo", null).get())
    );
  }

  @Test
  public void test_taskStatuses_RUNNING_foo_zero() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(
            HttpMethod.GET,
            "/druid/indexer/v1/tasks?state=RUNNING&datasource=foo%3F&max=0"
        ),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(STATUSES)
    );

    Assert.assertEquals(
        STATUSES,
        ImmutableList.copyOf(overlordClient.taskStatuses("RUNNING", "foo?", 0).get())
    );
  }

  @Test
  public void test_taskStatuses_null_null_zero() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(
            HttpMethod.GET,
            "/druid/indexer/v1/tasks?max=0"
        ),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(STATUSES)
    );

    Assert.assertEquals(
        STATUSES,
        ImmutableList.copyOf(overlordClient.taskStatuses(null, null, 0).get())
    );
  }

  @Test
  public void test_findLockedIntervals() throws Exception
  {
    final Map<String, List<Interval>> lockMap =
        ImmutableMap.of("foo", Collections.singletonList(Intervals.of("2000/2001")));
    final List<LockFilterPolicy> requests = ImmutableList.of(
        new LockFilterPolicy("foo", 3, null, null)
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, "/druid/indexer/v1/lockedIntervals/v2")
            .jsonContent(jsonMapper, requests),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(lockMap)
    );

    Assert.assertEquals(
        lockMap,
        overlordClient.findLockedIntervals(requests).get()
    );
  }

  @Test
  public void test_findLockedIntervals_nullReturn() throws Exception
  {
    final List<LockFilterPolicy> requests = ImmutableList.of(
        new LockFilterPolicy("foo", 3, null, null)
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, "/druid/indexer/v1/lockedIntervals/v2")
            .jsonContent(jsonMapper, requests),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(null)
    );

    Assert.assertEquals(
        Collections.emptyMap(),
        overlordClient.findLockedIntervals(requests).get()
    );
  }

  @Test
  public void test_postSupervisor() throws Exception
  {
    final String supervisorId = "wiki_supervisor";
    final SupervisorSpec supervisorSpec = new TestSupervisorSpec(supervisorId, "data");

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, "/druid/indexer/v1/supervisor?skipRestartIfUnmodified=true")
            .jsonContent(jsonMapper, supervisorSpec),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(Map.of("id", supervisorId))
    );

    Assert.assertEquals(
        Map.of("id", supervisorId),
        overlordClient.postSupervisor(supervisorSpec).get()
    );
  }

  @Test
  public void test_supervisorStatuses() throws Exception
  {
    final List<SupervisorStatus> statuses = ImmutableList.of(
        new SupervisorStatus.Builder()
            .withId("foo")
            .withSource("kafka")
            .withState("chill")
            .build()
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/supervisor?system"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(statuses)
    );

    Assert.assertEquals(
        statuses,
        ImmutableList.copyOf(overlordClient.supervisorStatuses().get())
    );
  }

  @Test
  public void test_taskReportAsMap() throws Exception
  {
    final String taskId = "testTaskId";
    final TaskReport.ReportMap response = TaskReport.buildTaskReports(new KillTaskReport("taskId", null));

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/task/testTaskId/reports"),
        HttpResponseStatus.OK,
        ImmutableMap.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
        jsonMapper.writeValueAsBytes(response)
    );

    final ListenableFuture<TaskReport.ReportMap> future = overlordClient.taskReportAsMap(taskId);
    Assert.assertEquals(response, future.get());
  }

  @Test
  public void test_taskReportAsMap_notFound()
  {
    String taskId = "testTaskId";
    String errorMsg = "No task reports were found for this task. "
                      + "The task may not exist, or it may not have completed yet.";

    serviceClient.expectAndThrow(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/task/testTaskId/reports"),
        new HttpResponseException(
            new StringFullResponseHolder(
                new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND),
                StandardCharsets.UTF_8
            ).addChunk(errorMsg)
        )
    );

    final ListenableFuture<TaskReport.ReportMap> future = overlordClient.taskReportAsMap(taskId);

    final ExecutionException e = Assert.assertThrows(
        ExecutionException.class,
        future::get
    );

    MatcherAssert.assertThat(e.getCause(), CoreMatchers.instanceOf(HttpResponseException.class));
    Assert.assertEquals(
        HttpResponseStatus.NOT_FOUND.getCode(),
        ((HttpResponseException) e.getCause()).getResponse().getStatus().getCode()
    );
  }

  @Test
  public void test_getTaskReport_empty()
  {
    final String taskID = "testTaskId";

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/task/" + taskID + "/reports"),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        StringUtils.toUtf8("{}")
    );

    final TaskReport.ReportMap actualResponse =
        FutureUtils.getUnchecked(overlordClient.taskReportAsMap(taskID), true);
    Assert.assertEquals(Collections.emptyMap(), actualResponse);
  }

  @Test
  public void test_getTotalWorkerCapacity() throws Exception
  {
    int currentClusterCapacity = 5;
    int maximumCapacityWithAutoScale = 10;

    // Mock response for /druid/indexer/v1/totalWorkerCapacity
    final IndexingTotalWorkerCapacityInfo indexingTotalWorkerCapacityInfo = new IndexingTotalWorkerCapacityInfo(
        currentClusterCapacity,
        maximumCapacityWithAutoScale
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/totalWorkerCapacity"),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        jsonMapper.writeValueAsBytes(indexingTotalWorkerCapacityInfo)
    );

    Assert.assertEquals(
        indexingTotalWorkerCapacityInfo,
        FutureUtils.getUnchecked(overlordClient.getTotalWorkerCapacity(), true)
    );
  }

  @Test
  public void test_getWorkers() throws Exception
  {
    final List<IndexingWorkerInfo> workers = ImmutableList.of(
        new IndexingWorkerInfo(
            new IndexingWorker("http", "localhost", "1.2.3.4", 3, "2"),
            0,
            Collections.emptySet(),
            Collections.emptyList(),
            DateTimes.of("2000"),
            null
        )
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/workers"),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        jsonMapper.writeValueAsBytes(workers)
    );

    Assert.assertEquals(
        workers,
        FutureUtils.getUnchecked(overlordClient.getWorkers(), true)
    );
  }

  @Test
  public void test_killPendingSegments() throws Exception
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(
            HttpMethod.DELETE,
            "/druid/indexer/v1/pendingSegments/foo?interval=2000-01-01T00%3A00%3A00.000Z%2F2001-01-01T00%3A00%3A00.000Z"
        ),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        jsonMapper.writeValueAsBytes(
            ImmutableMap.of("numDeleted", 2L)
        )
    );

    Assert.assertEquals(
        Integer.valueOf(2),
        FutureUtils.getUnchecked(overlordClient.killPendingSegments("foo", Intervals.of("2000/2001")), true)
    );
  }

  @Test
  public void test_taskPayload() throws ExecutionException, InterruptedException, JsonProcessingException
  {
    final String taskID = "taskId_1";
    final ClientTaskQuery clientTaskQuery = new ClientKillUnusedSegmentsTaskQuery(
        taskID,
        "test",
        null,
        null,
        null,
        null,
        null
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/task/" + taskID),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new TaskPayloadResponse(taskID, clientTaskQuery))
    );

    Assert.assertEquals(
        clientTaskQuery,
        overlordClient.taskPayload(taskID).get().getPayload()
    );
  }

  @Test
  public void test_isCompactionSupervisorEnabled()
      throws JsonProcessingException, ExecutionException, InterruptedException
  {
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/compaction/isSupervisorEnabled"),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(false)
    );

    Assert.assertFalse(overlordClient.isCompactionSupervisorEnabled().get());
  }

  @Test
  public void test_getClusterCompactionConfig()
      throws JsonProcessingException, ExecutionException, InterruptedException
  {
    final ClusterCompactionConfig config = new ClusterCompactionConfig(
        0.2,
        101,
        new NewestSegmentFirstPolicy(null),
        true,
        CompactionEngine.MSQ
    );
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.GET, "/druid/indexer/v1/compaction/config/cluster"),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(config)
    );

    Assert.assertEquals(
        config,
        overlordClient.getClusterCompactionConfig().get()
    );
  }

  @Test
  public void test_updateClusterCompactionConfig()
      throws ExecutionException, InterruptedException, JsonProcessingException
  {
    final ClusterCompactionConfig config = new ClusterCompactionConfig(null, null, null, null, null);
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, "/druid/indexer/v1/compaction/config/cluster")
            .jsonContent(jsonMapper, config),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new UpdateResponse(true))
    );

    Assert.assertTrue(
        overlordClient.updateClusterCompactionConfig(config).get().isSuccess()
    );
  }

  @Test
  public void test_markSegmentAsUsed() throws Exception
  {
    final DataSegment wikiSegment = DataSegment.builder()
                                               .dataSource(TestDataSource.WIKI)
                                               .interval(Intervals.of("2024-12-01/P1D"))
                                               .version("v1")
                                               .size(100)
                                               .build();

    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s/segments/%s",
        TestDataSource.WIKI, StringUtils.urlEncode(wikiSegment.getId().toString())
    );
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, url),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(1))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(1),
        overlordClient.markSegmentAsUsed(wikiSegment.getId()).get()
    );
  }

  @Test
  public void test_markSegmentAsUnused() throws Exception
  {
    final DataSegment wikiSegment = DataSegment.builder()
                                               .dataSource(TestDataSource.WIKI)
                                               .interval(Intervals.of("2024-12-01/P1D"))
                                               .version("v1")
                                               .size(100)
                                               .build();

    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s/segments/%s",
        TestDataSource.WIKI, StringUtils.urlEncode(wikiSegment.getId().toString())
    );
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.DELETE, url),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(1))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(1),
        overlordClient.markSegmentAsUnused(wikiSegment.getId()).get()
    );
  }

  @Test
  public void test_markNonOvershadowedSegmentsAsUsed_bySegmentIds() throws Exception
  {
    final DataSegment wikiSegment = DataSegment.builder()
                                               .dataSource(TestDataSource.WIKI)
                                               .interval(Intervals.of("2024-12-01/P1D"))
                                               .version("v1")
                                               .size(100)
                                               .build();

    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s/markUsed",
        TestDataSource.WIKI
    );

    final SegmentsToUpdateFilter segmentFilter = new SegmentsToUpdateFilter(
        null,
        Collections.singleton(wikiSegment.getId().toString()),
        null
    );
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, url)
            .jsonContent(jsonMapper, segmentFilter),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(1))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(1),
        overlordClient.markNonOvershadowedSegmentsAsUsed(TestDataSource.WIKI, segmentFilter).get()
    );
  }

  @Test
  public void test_markSegmentsAsUnused_bySegmentIds() throws Exception
  {
    final DataSegment wikiSegment = DataSegment.builder()
                                               .dataSource(TestDataSource.WIKI)
                                               .interval(Intervals.of("2024-12-01/P1D"))
                                               .version("v1")
                                               .size(100)
                                               .build();

    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s/markUnused",
        TestDataSource.WIKI
    );

    final SegmentsToUpdateFilter segmentFilter = new SegmentsToUpdateFilter(
        null,
        Collections.singleton(wikiSegment.getId().toString()),
        null
    );
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, url)
            .jsonContent(jsonMapper, segmentFilter),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(1))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(1),
        overlordClient.markSegmentsAsUnused(TestDataSource.WIKI, segmentFilter).get()
    );
  }

  @Test
  public void test_markNonOvershadowedSegmentsAsUsed_byInterval() throws Exception
  {
    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s/markUsed",
        TestDataSource.WIKI
    );

    final SegmentsToUpdateFilter segmentFilter
        = new SegmentsToUpdateFilter(Intervals.of("2024/P1Y"), null, null);
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, url)
            .jsonContent(jsonMapper, segmentFilter),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(3))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(3),
        overlordClient.markNonOvershadowedSegmentsAsUsed(TestDataSource.WIKI, segmentFilter).get()
    );
  }

  @Test
  public void test_markSegmentsAsUnused_byInterval() throws Exception
  {
    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s/markUnused",
        TestDataSource.WIKI
    );

    final SegmentsToUpdateFilter segmentFilter
        = new SegmentsToUpdateFilter(Intervals.of("2024/P1Y"), null, null);
    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, url)
            .jsonContent(jsonMapper, segmentFilter),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(5))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(5),
        overlordClient.markSegmentsAsUnused(TestDataSource.WIKI, segmentFilter).get()
    );
  }

  @Test
  public void test_markNonOvershadowedSegmentsAsUsed_byDatasource() throws Exception
  {
    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s",
        TestDataSource.WIKI
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.POST, url),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(10))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(10),
        overlordClient.markNonOvershadowedSegmentsAsUsed(TestDataSource.WIKI).get()
    );
  }

  @Test
  public void test_markSegmentsAsUnused_byDatasource() throws Exception
  {
    final String url = StringUtils.format(
        "/druid/indexer/v1/datasources/%s",
        TestDataSource.WIKI
    );

    serviceClient.expectAndRespond(
        new RequestBuilder(HttpMethod.DELETE, url),
        HttpResponseStatus.OK,
        Collections.emptyMap(),
        DefaultObjectMapper.INSTANCE.writeValueAsBytes(new SegmentUpdateResponse(11))
    );

    Assert.assertEquals(
        new SegmentUpdateResponse(11),
        overlordClient.markSegmentsAsUnused(TestDataSource.WIKI).get()
    );
  }
}
