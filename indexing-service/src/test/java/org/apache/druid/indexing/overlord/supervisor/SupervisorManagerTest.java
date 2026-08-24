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

package org.apache.druid.indexing.overlord.supervisor;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.SettableFuture;
import org.apache.druid.error.DruidException;
import org.apache.druid.error.DruidExceptionMatcher;
import org.apache.druid.error.InvalidInput;
import org.apache.druid.guice.SupervisorModule;
import org.apache.druid.indexing.common.TaskLockType;
import org.apache.druid.indexing.common.task.Tasks;
import org.apache.druid.indexing.compact.CompactionScheduler;
import org.apache.druid.indexing.compact.CompactionSupervisorSpec;
import org.apache.druid.indexing.overlord.DataSourceMetadata;
import org.apache.druid.indexing.overlord.supervisor.autoscaler.SupervisorTaskAutoScaler;
import org.apache.druid.indexing.seekablestream.SeekableStreamStartSequenceNumbers;
import org.apache.druid.indexing.seekablestream.TestSeekableStreamDataSourceMetadata;
import org.apache.druid.indexing.seekablestream.supervisor.SeekableStreamSupervisor;
import org.apache.druid.indexing.seekablestream.supervisor.SeekableStreamSupervisorSpec;
import org.apache.druid.jackson.DefaultObjectMapper;
import org.apache.druid.java.util.common.DateTimes;
import org.apache.druid.java.util.common.Intervals;
import org.apache.druid.java.util.emitter.EmittingLogger;
import org.apache.druid.java.util.emitter.service.AlertEvent;
import org.apache.druid.java.util.metrics.StubServiceEmitter;
import org.apache.druid.metadata.MetadataSupervisorManager;
import org.apache.druid.metadata.PendingSegmentRecord;
import org.apache.druid.segment.realtime.appenderator.SegmentIdWithShardSpec;
import org.apache.druid.server.coordinator.InlineSchemaDataSourceCompactionConfig;
import org.apache.druid.timeline.partition.NumberedShardSpec;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.EasyMockSupport;
import org.easymock.Mock;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RunWith(EasyMockRunner.class)
public class SupervisorManagerTest extends EasyMockSupport
{
  private static final ObjectMapper MAPPER = new DefaultObjectMapper();

  @Mock
  private MetadataSupervisorManager metadataSupervisorManager;

  @Mock
  private StreamSupervisor supervisor1;

  @Mock
  private StreamSupervisor supervisor2;

  @Mock
  private Supervisor supervisor3;

  private SupervisorManager manager;
  private StubServiceEmitter emitter;

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Before
  public void setUp()
  {
    emitter = new StubServiceEmitter("supervisor-manager-test", "localhost");
    EmittingLogger.registerEmitter(emitter);
    manager = new SupervisorManager(MAPPER, metadataSupervisorManager);
  }

  @Test
  public void testCreateUpdateAndRemoveSupervisor()
  {
    SupervisorSpec spec = new TestSupervisorSpec("id1", supervisor1);
    SupervisorSpec spec2 = new TestSupervisorSpec("id1", supervisor2);
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id3", new TestSupervisorSpec("id3", supervisor3)
    );

    Assert.assertTrue(manager.getSupervisorIds().isEmpty());

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    metadataSupervisorManager.insert("id1", spec);
    supervisor3.start();
    EasyMock.expect(supervisor3.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    replayAll();

    manager.start();
    Assert.assertEquals(1, manager.getSupervisorIds().size());

    manager.createOrUpdateAndStartSupervisor(spec);
    Assert.assertEquals(2, manager.getSupervisorIds().size());
    Assert.assertEquals(spec, manager.getSupervisorSpec("id1").get());
    verifyAll();

    resetAll();
    supervisor2.start();
    EasyMock.expect(supervisor2.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.stop(true);
    replayAll();

    manager.createOrUpdateAndStartSupervisor(spec2);
    Assert.assertEquals(2, manager.getSupervisorIds().size());
    Assert.assertEquals(spec2, manager.getSupervisorSpec("id1").get());
    verifyAll();

    resetAll();
    metadataSupervisorManager.insert(EasyMock.eq("id1"), EasyMock.anyObject(NoopSupervisorSpec.class));
    supervisor2.stop(true);
    replayAll();

    boolean retVal = manager.stopAndRemoveSupervisor("id1");
    Assert.assertTrue(retVal);
    Assert.assertEquals(1, manager.getSupervisorIds().size());
    Assert.assertEquals(Optional.absent(), manager.getSupervisorSpec("id1"));
    verifyAll();

    resetAll();
    SettableFuture<Void> stopFuture = SettableFuture.create();
    stopFuture.set(null);
    EasyMock.expect(supervisor3.stopAsync()).andReturn(stopFuture);
    replayAll();

    manager.stop();
    verifyAll();

    Assert.assertTrue(manager.getSupervisorIds().isEmpty());
  }

  @Test
  public void testCreateOrUpdateAndStartSupervisorIllegalEvolution()
  {
    SupervisorSpec spec = new TestSupervisorSpec("id1", supervisor1)
    {
      @Override
      public void validateSpecUpdateTo(SupervisorSpec proposedSpec) throws DruidException
      {
        throw InvalidInput.exception("Illegal spec update proposed");
      }
    };
    SupervisorSpec spec2 = new TestSupervisorSpec("id1", supervisor2);

    Assert.assertTrue(manager.getSupervisorIds().isEmpty());

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(ImmutableMap.of());
    metadataSupervisorManager.insert("id1", spec);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    replayAll();

    manager.start();
    Assert.assertEquals(0, manager.getSupervisorIds().size());

    manager.createOrUpdateAndStartSupervisor(spec);
    Assert.assertEquals(1, manager.getSupervisorIds().size());
    Assert.assertEquals(spec, manager.getSupervisorSpec("id1").get());
    verifyAll();

    resetAll();
    exception.expect(DruidException.class);
    replayAll();

    manager.createOrUpdateAndStartSupervisor(spec2);
    verifyAll();
  }

  @Test
  public void testCreateOrUpdateAndStartSupervisorNotStarted()
  {
    exception.expect(IllegalStateException.class);
    manager.createOrUpdateAndStartSupervisor(new TestSupervisorSpec("id", null));
  }

  @Test
  public void testCreateOrUpdateAndStartSupervisorNullSpec()
  {
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(ImmutableMap.of());
    replayAll();

    exception.expect(NullPointerException.class);

    manager.start();
    manager.createOrUpdateAndStartSupervisor(null);
    verifyAll();
  }

  @Test
  public void testCreateOrUpdateAndStartSupervisorNullSpecId()
  {
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(ImmutableMap.of());
    replayAll();

    exception.expect(NullPointerException.class);

    manager.start();
    manager.createOrUpdateAndStartSupervisor(new TestSupervisorSpec(null, null));
    verifyAll();
  }

  @Test
  public void testShouldUpdateSupervisor()
  {
    SupervisorSpec spec = new TestSupervisorSpec("id1", supervisor1);
    SupervisorSpec spec2 = new TestSupervisorSpec("id2", supervisor2);
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", spec
    );
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    replayAll();
    manager.start();
    Assert.assertFalse(manager.shouldUpdateSupervisor(spec));
    Assert.assertTrue(manager.shouldUpdateSupervisor(spec2));
    Assert.assertTrue(manager.shouldUpdateSupervisor(new NoopSupervisorSpec("id1", null)));
  }

  @Test
  public void testShouldUpdateSupervisorIllegalEvolution()
  {
    SupervisorSpec spec = new TestSupervisorSpec("id1", supervisor1)
    {
      @Override
      public void validateSpecUpdateTo(SupervisorSpec proposedSpec) throws DruidException
      {
        throw InvalidInput.exception("Illegal spec update proposed");
      }
    };
    SupervisorSpec spec2 = new TestSupervisorSpec("id1", supervisor2);
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", spec
    );
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    exception.expect(DruidException.class);
    replayAll();
    manager.start();
    manager.shouldUpdateSupervisor(spec2);
    verifyAll();
  }

  @Test
  public void testStopAndRemoveSupervisorNotStarted()
  {
    exception.expect(IllegalStateException.class);
    manager.stopAndRemoveSupervisor("id");
  }

  @Test
  public void testStopAndRemoveSupervisorNullSpecId()
  {
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(ImmutableMap.of());
    replayAll();

    exception.expect(NullPointerException.class);

    manager.start();
    manager.stopAndRemoveSupervisor(null);
    verifyAll();
  }

  @Test
  public void testGetSupervisorHistory()
  {
    Map<String, List<VersionedSupervisorSpec>> supervisorHistory = ImmutableMap.of();

    EasyMock.expect(metadataSupervisorManager.getAll()).andReturn(supervisorHistory);
    replayAll();

    Map<String, List<VersionedSupervisorSpec>> history = manager.getSupervisorHistory();
    verifyAll();

    Assert.assertEquals(supervisorHistory, history);
  }

  @Test
  public void testGetSupervisorHistoryForId()
  {
    String id = "test-supervisor-1";
    List<VersionedSupervisorSpec> supervisorHistory = ImmutableList.of();

    EasyMock.expect(metadataSupervisorManager.getAllForId(id, null)).andReturn(supervisorHistory);
    replayAll();

    List<VersionedSupervisorSpec> history = manager.getSupervisorHistoryForId(id, null);
    verifyAll();

    Assert.assertEquals(supervisorHistory, history);
  }

  @Test
  public void testGetSupervisorHistoryForIdWithLimit()
  {
    String id = "test-supervisor-1";
    Integer limit = 5;
    List<VersionedSupervisorSpec> supervisorHistory = ImmutableList.of();

    EasyMock.expect(metadataSupervisorManager.getAllForId(id, limit)).andReturn(supervisorHistory);
    replayAll();

    List<VersionedSupervisorSpec> history = manager.getSupervisorHistoryForId(id, limit);
    verifyAll();

    Assert.assertEquals(supervisorHistory, history);
  }

  @Test
  public void testGetSupervisorStatus()
  {
    SupervisorReport<Void> report = new SupervisorReport<>("id1", DateTimes.nowUtc(), null);

    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", new TestSupervisorSpec("id1", supervisor1)
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    EasyMock.expect(supervisor1.getStatus()).andReturn(report);
    replayAll();

    manager.start();

    Assert.assertEquals(Optional.absent(), manager.getSupervisorStatus("non-existent-id"));
    Assert.assertEquals(report, manager.getSupervisorStatus("id1").get());

    verifyAll();
  }

  @Test
  public void testHandoffTaskGroupsEarly()
  {
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", new TestSupervisorSpec("id1", supervisor1)
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.handoffTaskGroupsEarly(ImmutableList.of(1));

    replayAll();

    manager.start();

    Assert.assertTrue(manager.handoffTaskGroupsEarly("id1", ImmutableList.of(1)));
    Assert.assertFalse(manager.handoffTaskGroupsEarly("id2", ImmutableList.of(1)));

    verifyAll();
  }

  @Test
  public void testHandoffTaskGroupsEarlyOnNonStreamSupervisor()
  {
    final Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id3", new TestSupervisorSpec("id3", supervisor3)
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor3.start();
    EasyMock.expect(supervisor3.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();

    replayAll();

    manager.start();

    MatcherAssert.assertThat(
        Assert.assertThrows(DruidException.class, () -> manager.handoffTaskGroupsEarly("id3", ImmutableList.of(1))),
        new DruidExceptionMatcher(
            DruidException.Persona.USER,
            DruidException.Category.UNSUPPORTED,
            "general"
        ).expectMessageIs(
                "Operation[handoff] is not supported by supervisor[id3] of type[TestSupervisorSpec]."
        )
    );
    verifyAll();
  }

  @Test
  public void testStartAlreadyStarted()
  {
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(ImmutableMap.of());
    replayAll();

    exception.expect(IllegalStateException.class);

    manager.start();
    manager.start();
  }

  @Test
  public void testStartIndividualSupervisorsFailStart()
  {
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", new TestSupervisorSpec("id1", supervisor1),
        "id3", new TestSupervisorSpec("id3", supervisor3)
    );


    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor3.start();
    EasyMock.expect(supervisor3.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.start();
    EasyMock.expectLastCall().andThrow(new RuntimeException("supervisor explosion"));
    replayAll();

    manager.start();

    // if we get here, we are properly insulated from exploding supervisors
  }

  @Test
  public void testNoPersistOnFailedStart()
  {
    exception.expect(RuntimeException.class);

    Capture<TestSupervisorSpec> capturedInsert = Capture.newInstance();

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(Collections.emptyMap());
    metadataSupervisorManager.insert(EasyMock.eq("id1"), EasyMock.capture(capturedInsert));
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.stop(true);
    EasyMock.expect(supervisor2.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor2.start();
    EasyMock.expectLastCall().andThrow(new RuntimeException("supervisor failed to start"));
    replayAll();

    final SupervisorSpec testSpecOld = new TestSupervisorSpec("id1", supervisor1);
    final SupervisorSpec testSpecNew = new TestSupervisorSpec("id1", supervisor2);

    manager.start();
    try {
      manager.createOrUpdateAndStartSupervisor(testSpecOld);
      manager.createOrUpdateAndStartSupervisor(testSpecNew);
    }
    catch (Exception e) {
      Assert.assertEquals(testSpecOld, capturedInsert.getValue());
      throw e;
    }
  }

  @Test
  public void testStopThrowsException()
  {
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", new TestSupervisorSpec("id1", supervisor1)
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.stopAsync();
    EasyMock.expectLastCall().andThrow(new RuntimeException("RTE"));
    replayAll();

    manager.start();
    manager.stop();
    verifyAll();
  }

  @Test
  public void testResetSupervisor()
  {
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", new TestSupervisorSpec("id1", supervisor1)
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.reset(EasyMock.anyObject(DataSourceMetadata.class));
    replayAll();

    manager.start();
    Assert.assertTrue("resetValidSupervisor", manager.resetSupervisor("id1", null));
    Assert.assertFalse("resetInvalidSupervisor", manager.resetSupervisor("nobody_home", null));

    verifyAll();
  }

  @Test
  public void testResetOnNonStreamSupervisor()
  {
    final Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id3", new TestSupervisorSpec("id3", supervisor3)
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor3.start();
    EasyMock.expect(supervisor3.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    replayAll();

    manager.start();

    MatcherAssert.assertThat(
        Assert.assertThrows(DruidException.class, () -> manager.resetSupervisor("id3", null)),
        new DruidExceptionMatcher(
            DruidException.Persona.USER,
            DruidException.Category.UNSUPPORTED,
            "general"
        ).expectMessageIs(
            "Operation[reset] is not supported by supervisor[id3] of type[TestSupervisorSpec]."
        )
    );

    verifyAll();
  }

  @Test
  public void testResetSupervisorWithSpecificOffsets()
  {
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id1", new TestSupervisorSpec("id1", supervisor1)
    );

    DataSourceMetadata datasourceMetadata = new TestSeekableStreamDataSourceMetadata(
        new SeekableStreamStartSequenceNumbers<>(
            "topic",
            ImmutableMap.of("0", "10", "1", "20", "2", "30"),
            ImmutableSet.of()
        )
    );

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.resetOffsets(datasourceMetadata);
    replayAll();

    manager.start();
    Assert.assertTrue("resetValidSupervisor", manager.resetSupervisor("id1", datasourceMetadata));
    Assert.assertFalse("resetInvalidSupervisor", manager.resetSupervisor("nobody_home", datasourceMetadata));

    verifyAll();
  }

  @Test
  public void testCreateSuspendResumeAndStopSupervisor()
  {
    Capture<TestSupervisorSpec> capturedInsert = Capture.newInstance();
    SupervisorSpec spec = new TestSupervisorSpec("id1", supervisor1, false, supervisor2);
    Map<String, SupervisorSpec> existingSpecs = ImmutableMap.of(
        "id3", new TestSupervisorSpec("id3", supervisor3)
    );

    // mock adding a supervisor to manager with existing supervisor then suspending it
    Assert.assertTrue(manager.getSupervisorIds().isEmpty());

    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(existingSpecs);
    metadataSupervisorManager.insert("id1", spec);
    supervisor3.start();
    EasyMock.expect(supervisor3.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    replayAll();

    manager.start();
    Assert.assertEquals(1, manager.getSupervisorIds().size());

    manager.createOrUpdateAndStartSupervisor(spec);
    Assert.assertEquals(2, manager.getSupervisorIds().size());
    Assert.assertEquals(spec, manager.getSupervisorSpec("id1").get());
    verifyAll();

    // mock suspend, which stops supervisor1 and sets suspended state in metadata, flipping to supervisor2
    // in TestSupervisorSpec implementation of createSuspendedSpec
    resetAll();
    metadataSupervisorManager.insert(EasyMock.eq("id1"), EasyMock.capture(capturedInsert));
    supervisor2.start();
    EasyMock.expect(supervisor2.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    supervisor1.stop(true);
    replayAll();

    manager.suspendOrResumeSupervisor("id1", true);
    Assert.assertEquals(2, manager.getSupervisorIds().size());
    Assert.assertEquals(capturedInsert.getValue(), manager.getSupervisorSpec("id1").get());
    Assert.assertTrue(capturedInsert.getValue().suspended);
    verifyAll();

    // mock resume, which stops supervisor2 and sets suspended to false in metadata, flipping to supervisor1
    // in TestSupervisorSpec implementation of createRunningSpec
    resetAll();
    metadataSupervisorManager.insert(EasyMock.eq("id1"), EasyMock.capture(capturedInsert));
    supervisor2.stop(true);
    supervisor1.start();
    EasyMock.expect(supervisor1.createAutoscaler(EasyMock.anyObject())).andReturn(null).anyTimes();
    replayAll();

    manager.suspendOrResumeSupervisor("id1", false);
    Assert.assertEquals(2, manager.getSupervisorIds().size());
    Assert.assertEquals(capturedInsert.getValue(), manager.getSupervisorSpec("id1").get());
    Assert.assertFalse(capturedInsert.getValue().suspended);
    verifyAll();

    // mock stop of suspended then resumed supervisor
    resetAll();
    metadataSupervisorManager.insert(EasyMock.eq("id1"), EasyMock.anyObject(NoopSupervisorSpec.class));
    supervisor1.stop(true);
    replayAll();

    boolean retVal = manager.stopAndRemoveSupervisor("id1");
    Assert.assertTrue(retVal);
    Assert.assertEquals(1, manager.getSupervisorIds().size());
    Assert.assertEquals(Optional.absent(), manager.getSupervisorSpec("id1"));
    verifyAll();

    // mock manager shutdown to ensure supervisor 3 stops
    resetAll();
    SettableFuture<Void> stopFuture = SettableFuture.create();
    stopFuture.set(null);
    EasyMock.expect(supervisor3.stopAsync()).andReturn(stopFuture);
    replayAll();

    manager.stop();
    verifyAll();

    Assert.assertTrue(manager.getSupervisorIds().isEmpty());
  }

  @Test
  public void testSuspendTransitionPersistsBeforeStoppingAndReplacesRuntime()
  {
    final List<String> events = new ArrayList<>();
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager(events);
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final SupervisorTaskAutoScaler oldAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final SupervisorTaskAutoScaler replacementAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        replacementSupervisor
    );
    previousSpec.suspendedSpec = nextSpec;

    startManager(metadata, previousSpec, oldSupervisor, oldAutoscaler);
    events.clear();

    oldAutoscaler.stop();
    EasyMock.expectLastCall().andAnswer(() -> {
      events.add("oldAutoscaler.stop");
      return null;
    });
    oldSupervisor.stop(true);
    EasyMock.expectLastCall().andAnswer(() -> {
      events.add("oldSupervisor.stop");
      return null;
    });
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(replacementAutoscaler);
    replacementSupervisor.start();
    EasyMock.expectLastCall().andAnswer(() -> {
      Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
      events.add("replacementSupervisor.start");
      return null;
    });
    replacementAutoscaler.start();
    EasyMock.expectLastCall().andAnswer(() -> {
      events.add("replacementAutoscaler.start");
      return null;
    });
    EasyMock.replay(oldSupervisor, oldAutoscaler, replacementSupervisor, replacementAutoscaler);

    Assert.assertTrue(manager.suspendOrResumeSupervisor("id", true));
    Assert.assertSame(nextSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(
        ImmutableList.of(
            "insert:suspended",
            "oldAutoscaler.stop",
            "oldSupervisor.stop",
            "replacementSupervisor.start",
            "replacementAutoscaler.start"
        ),
        events
    );
    EasyMock.verify(oldSupervisor, oldAutoscaler, replacementSupervisor, replacementAutoscaler);
  }

  @Test
  public void testResumeTransitionPersistsBeforeStoppingAndReplacesRuntime()
  {
    final List<String> events = new ArrayList<>();
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager(events);
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final SupervisorTaskAutoScaler oldAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final SupervisorTaskAutoScaler replacementAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        oldSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        replacementSupervisor
    );
    previousSpec.runningSpec = nextSpec;

    startManager(metadata, previousSpec, oldSupervisor, oldAutoscaler);
    events.clear();

    oldAutoscaler.stop();
    EasyMock.expectLastCall().andAnswer(() -> {
      events.add("oldAutoscaler.stop");
      return null;
    });
    oldSupervisor.stop(true);
    EasyMock.expectLastCall().andAnswer(() -> {
      events.add("oldSupervisor.stop");
      return null;
    });
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(replacementAutoscaler);
    replacementSupervisor.start();
    EasyMock.expectLastCall().andAnswer(() -> {
      Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
      events.add("replacementSupervisor.start");
      return null;
    });
    replacementAutoscaler.start();
    EasyMock.expectLastCall().andAnswer(() -> {
      events.add("replacementAutoscaler.start");
      return null;
    });
    EasyMock.replay(oldSupervisor, oldAutoscaler, replacementSupervisor, replacementAutoscaler);

    Assert.assertTrue(manager.suspendOrResumeSupervisor("id", false));
    Assert.assertSame(nextSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(
        ImmutableList.of(
            "insert:running",
            "oldAutoscaler.stop",
            "oldSupervisor.stop",
            "replacementSupervisor.start",
            "replacementAutoscaler.start"
        ),
        events
    );
    EasyMock.verify(oldSupervisor, oldAutoscaler, replacementSupervisor, replacementAutoscaler);
  }

  @Test
  public void testResumeTransitionInsertFailureLeavesRuntimeUntouched()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor);
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.runningSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.addInsertFailure(false, insertFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", false))
    );
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertEquals(1, metadata.inserts.size());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testResumeReplacementStartFailureRestoresPreviousRuntime()
  {
    final RuntimeException startFailure = new RuntimeException("replacement start failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        oldSupervisor,
        restoredSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        replacementSupervisor
    );
    previousSpec.runningSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(null);
    replacementSupervisor.start();
    EasyMock.expectLastCall().andThrow(startFailure);
    replacementSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andReturn(null);
    restoredSupervisor.start();
    EasyMock.replay(oldSupervisor, restoredSupervisor, replacementSupervisor);

    Assert.assertSame(
        startFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", false))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, restoredSupervisor, replacementSupervisor);
  }

  @Test
  public void testSuspendOrResumeNoopWithMatchingMetadataDoesNotPersistOrRestartRuntime()
  {
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec runningSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    startManager(metadata, runningSpec, oldSupervisor, null);

    EasyMock.replay(oldSupervisor);
    Assert.assertFalse(manager.suspendOrResumeSupervisor("id", false));
    Assert.assertEquals(1, metadata.reads);
    Assert.assertEquals(0, metadata.inserts.size());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testSuspendOrResumeNoopIgnoresMetadataReadFailure()
  {
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec runningSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    startManager(metadata, runningSpec, oldSupervisor, null);
    metadata.readFailures.add(new RuntimeException("read failed"));

    EasyMock.replay(oldSupervisor);
    Assert.assertFalse(manager.suspendOrResumeSupervisor("id", false));
    Assert.assertEquals(1, metadata.reads);
    Assert.assertEquals(0, metadata.inserts.size());
    Assert.assertSame(runningSpec, manager.getSupervisorSpec("id").get());
    Assert.assertTrue(emitter.getAlerts().isEmpty());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testSuspendOrResumeNoopIgnoresMetadataRepairFailure()
  {
    final RuntimeException repairFailure = new RuntimeException("repair failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec runningSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    startManager(metadata, runningSpec, oldSupervisor, null);
    metadata.latest.put("id", new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor));
    metadata.addInsertFailure(false, repairFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertFalse(manager.suspendOrResumeSupervisor("id", false));
    Assert.assertEquals(1, metadata.inserts.size());
    Assert.assertSame(runningSpec, manager.getSupervisorSpec("id").get());
    Assert.assertTrue(emitter.getAlerts().isEmpty());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testSuspendOrResumeNoopDoesNotAlertWhenRepairFindsConcurrentTombstone()
  {
    final RuntimeException repairFailure = new RuntimeException("repair failed");
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec runningSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager()
    {
      @Override
      public void insert(String id, SupervisorSpec spec)
      {
        try {
          super.insert(id, spec);
        }
        catch (RuntimeException e) {
          setLatest(id, new NoopSupervisorSpec(id, runningSpec.getDataSources()));
          throw e;
        }
      }
    };
    startManager(metadata, runningSpec, oldSupervisor, null);
    metadata.latest.put("id", new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor));
    metadata.addInsertFailure(false, repairFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertFalse(manager.suspendOrResumeSupervisor("id", false));
    Assert.assertEquals(1, metadata.inserts.size());
    Assert.assertTrue(metadata.latest.get("id") instanceof NoopSupervisorSpec);
    Assert.assertSame(runningSpec, manager.getSupervisorSpec("id").get());
    Assert.assertTrue(emitter.getAlerts().isEmpty());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testGeneratedTransitionSpecMustPreserveId()
  {
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("different-id", true, "suspended", oldSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);

    EasyMock.replay(oldSupervisor);
    Assert.assertThrows(
        IllegalStateException.class,
        () -> manager.suspendOrResumeSupervisor("id", true)
    );
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(0, metadata.inserts.size());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testExactSpecComparisonSurvivesRealSpecJsonRoundTrip() throws Exception
  {
    final ObjectMapper mapper = new DefaultObjectMapper();
    final CompactionScheduler scheduler = EasyMock.createNiceMock(CompactionScheduler.class);
    EasyMock.replay(scheduler);
    mapper.setInjectableValues(new InjectableValues.Std().addValue(CompactionScheduler.class, scheduler));
    mapper.registerModules(new SupervisorModule().getJacksonModules());
    final SupervisorSpec expected = new CompactionSupervisorSpec(
        InlineSchemaDataSourceCompactionConfig.builder().forDataSource("datasource").build(),
        false,
        scheduler
    );
    final SupervisorSpec roundTripped = mapper.readValue(
        mapper.writeValueAsBytes(expected),
        SupervisorSpec.class
    );

    Assert.assertTrue(
        new SupervisorManager(mapper, metadataSupervisorManager).specsExactlyMatch(expected, roundTripped)
    );
  }

  @Test
  public void testTransitionInsertFailureWithPreviousSpecLeavesRuntimeUntouched()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.addInsertFailure(false, insertFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertEquals(1, metadata.inserts.size());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testTransitionInsertFailureRetainedWhenSpecComparisonFails()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final RuntimeException serializationFailure = new RuntimeException("serialization failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager()
    {
      @Override
      public void insert(String id, SupervisorSpec spec)
      {
        try {
          MAPPER.valueToTree(spec);
        }
        catch (IllegalArgumentException e) {
          throw insertFailure;
        }
        super.insert(id, spec);
      }
    };
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor);
    nextSpec.serializationFailure = serializationFailure;
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertEquals(1, insertFailure.getSuppressed().length);
    final Throwable comparisonFailure = insertFailure.getSuppressed()[0];
    Assert.assertEquals("Unable to serialize supervisor specs for exact metadata comparison", comparisonFailure.getMessage());
    Throwable rootCause = comparisonFailure;
    while (rootCause.getCause() != null) {
      rootCause = rootCause.getCause();
    }
    Assert.assertSame(serializationFailure, rootCause);
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testTransitionInsertCommitThenThrowContinues()
  {
    final RuntimeException insertFailure = new RuntimeException("commit then throw");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec("id", true, "suspended", replacementSupervisor);
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.addInsertFailure(true, insertFailure);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(null);
    replacementSupervisor.start();
    EasyMock.replay(oldSupervisor, replacementSupervisor);

    Assert.assertTrue(manager.suspendOrResumeSupervisor("id", true));
    Assert.assertSame(nextSpec, metadata.latest.get("id"));
    Assert.assertSame(nextSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, replacementSupervisor);
  }

  @Test
  public void testSuccessfulTransitionPersistsWithoutReadingMetadata()
  {
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec("id", true, "suspended", replacementSupervisor);
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.latest.put("id", nextSpec);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(null);
    replacementSupervisor.start();
    EasyMock.replay(oldSupervisor, replacementSupervisor);

    Assert.assertTrue(manager.suspendOrResumeSupervisor("id", true));
    Assert.assertEquals(0, metadata.reads);
    Assert.assertEquals(1, metadata.inserts.size());
    Assert.assertSame(nextSpec, metadata.latest.get("id"));
    Assert.assertSame(nextSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, replacementSupervisor);
  }

  @Test
  public void testTransitionInsertFailureWithUnknownLatestCompensatesPreviousSpec()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.latest.clear();
    metadata.addInsertFailure(false, insertFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(2, metadata.inserts.size());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testTransitionInsertFailureWithTombstoneDoesNotResurrectPreviousSpec()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.latest.put("id", new NoopSupervisorSpec("id", previousSpec.getDataSources()));
    metadata.addInsertFailure(false, insertFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertTrue(metadata.latest.get("id") instanceof NoopSupervisorSpec);
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(1, metadata.inserts.size());
    Assert.assertTrue(emitter.getAlerts().isEmpty());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testTransitionInsertFailureDoesNotAcceptSameStateWithDifferentConfiguration()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec("id", true, "requested", oldSupervisor);
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.latest.put("id", new TransitionSupervisorSpec("id", true, "different", oldSupervisor));
    metadata.addInsertFailure(false, insertFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertEquals(2, metadata.inserts.size());
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testTransitionInsertReadAndCompensationFailuresAreSuppressed()
  {
    final RuntimeException insertFailure = new RuntimeException("insert failed");
    final RuntimeException readFailure = new RuntimeException("read failed");
    final RuntimeException compensationFailure = new RuntimeException("compensation failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.latest.clear();
    metadata.addInsertFailure(false, insertFailure);
    metadata.readFailures.add(readFailure);
    metadata.addInsertFailure(false, compensationFailure);

    EasyMock.replay(oldSupervisor);
    Assert.assertSame(
        insertFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertEquals(2, insertFailure.getSuppressed().length);
    Assert.assertSame(readFailure, insertFailure.getSuppressed()[0]);
    Assert.assertSame(compensationFailure, insertFailure.getSuppressed()[1]);
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    assertTransitionAlert(
        "Unable to confirm metadata compensation for supervisor [id] after failure while "
        + "[persisting the transition spec], runtime state may differ from the latest metadata revision, "
        + "re-issue POST /supervisor/id/resume to reconcile",
        "persisting the transition spec"
    );
    EasyMock.verify(oldSupervisor);
  }

  @Test
  public void testAutoscalerStopFailureRollsBackMetadataAndKeepsOldEntry()
  {
    final RuntimeException stopFailure = new RuntimeException("autoscaler stop failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final SupervisorTaskAutoScaler oldAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", replacementSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, oldAutoscaler);

    oldAutoscaler.stop();
    EasyMock.expectLastCall().andThrow(stopFailure);
    EasyMock.replay(oldSupervisor, oldAutoscaler, replacementSupervisor);

    Assert.assertSame(
        stopFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    assertTransitionAlert(
        "Failed to stop previous runtime for supervisor [id]; runtime state is unverified and the existing "
        + "supervisor entry remains registered",
        "stopping the previous runtime"
    );
    EasyMock.verify(oldSupervisor, oldAutoscaler, replacementSupervisor);
  }

  @Test
  public void testSupervisorStopFailureKeepsEntryAndConfirmedCompensationFailureIsNotSuppressed()
  {
    final RuntimeException stopFailure = new RuntimeException("supervisor stop failed");
    final RuntimeException compensationFailure = new RuntimeException("commit then throw");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", replacementSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.addInsertSuccess();
    metadata.addInsertFailure(true, compensationFailure);

    oldSupervisor.stop(true);
    EasyMock.expectLastCall().andThrow(stopFailure);
    EasyMock.replay(oldSupervisor, replacementSupervisor);

    Assert.assertSame(
        stopFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(0, stopFailure.getSuppressed().length);
    assertTransitionAlert(
        "Failed to stop previous runtime for supervisor [id]; runtime state is unverified and the existing "
        + "supervisor entry remains registered",
        "stopping the previous runtime"
    );
    EasyMock.verify(oldSupervisor, replacementSupervisor);
  }

  @Test
  public void testStopFailureDoesNotCompensateOverConcurrentTombstone()
  {
    final RuntimeException stopFailure = new RuntimeException("supervisor stop failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", replacementSupervisor);
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expectLastCall().andAnswer(() -> {
      metadata.latest.put("id", new NoopSupervisorSpec("id", previousSpec.getDataSources()));
      throw stopFailure;
    });
    EasyMock.replay(oldSupervisor, replacementSupervisor);

    Assert.assertSame(
        stopFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertTrue(metadata.latest.get("id") instanceof NoopSupervisorSpec);
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    Assert.assertEquals(1, metadata.inserts.size());
    assertTransitionAlert(
        "Failed to stop previous runtime for supervisor [id]; runtime state is unverified and the existing "
        + "supervisor entry remains registered",
        "stopping the previous runtime"
    );
    EasyMock.verify(oldSupervisor, replacementSupervisor);
  }

  @Test
  public void testReplacementStartFailureCleansUpAndRestoresPreviousRuntimeAndAutoscaler()
  {
    final RuntimeException startFailure = new RuntimeException("replacement start failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final SupervisorTaskAutoScaler oldAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final SupervisorTaskAutoScaler restoredAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final SupervisorTaskAutoScaler replacementAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor,
        restoredSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        replacementSupervisor
    );
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, oldAutoscaler);

    oldAutoscaler.stop();
    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(replacementAutoscaler);
    replacementSupervisor.start();
    EasyMock.expectLastCall().andAnswer(() -> {
      Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
      throw startFailure;
    });
    replacementAutoscaler.stop();
    replacementSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andReturn(restoredAutoscaler);
    restoredSupervisor.start();
    restoredAutoscaler.start();
    EasyMock.replay(
        oldSupervisor,
        restoredSupervisor,
        replacementSupervisor,
        oldAutoscaler,
        restoredAutoscaler,
        replacementAutoscaler
    );

    Assert.assertSame(
        startFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(
        oldSupervisor,
        restoredSupervisor,
        replacementSupervisor,
        oldAutoscaler,
        restoredAutoscaler,
        replacementAutoscaler
    );
  }

  @Test
  public void testReplacementCreateSupervisorFailureRestoresPreviousRuntime()
  {
    final RuntimeException createFailure = new RuntimeException("create failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor,
        restoredSupervisor
    );
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor)
    {
      @Override
      public Supervisor createSupervisor()
      {
        throw createFailure;
      }
    };
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andReturn(null);
    restoredSupervisor.start();
    EasyMock.replay(oldSupervisor, restoredSupervisor);

    Assert.assertSame(
        createFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, restoredSupervisor);
  }

  @Test
  public void testReplacementCreateAutoscalerFailureCleansUpAndRestoresPreviousRuntime()
  {
    final RuntimeException autoscalerFailure = new RuntimeException("create autoscaler failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor,
        restoredSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        replacementSupervisor
    );
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andThrow(autoscalerFailure);
    replacementSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andReturn(null);
    restoredSupervisor.start();
    EasyMock.replay(oldSupervisor, restoredSupervisor, replacementSupervisor);

    Assert.assertSame(
        autoscalerFailure,
        Assert.assertThrows(RuntimeException.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, restoredSupervisor, replacementSupervisor);
  }

  @Test
  public void testUnconfirmedMetadataRollbackDoesNotPreventRuntimeRestoration()
  {
    final RuntimeException replacementFailure = new RuntimeException("replacement failed");
    final RuntimeException rollbackFailure = new RuntimeException("rollback failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor,
        restoredSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        replacementSupervisor
    );
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);
    metadata.addInsertSuccess();
    metadata.addInsertFailure(false, rollbackFailure);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andThrow(replacementFailure);
    replacementSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andReturn(null);
    restoredSupervisor.start();
    EasyMock.replay(oldSupervisor, restoredSupervisor, replacementSupervisor);

    final RuntimeException thrown = Assert.assertThrows(
        RuntimeException.class,
        () -> manager.suspendOrResumeSupervisor("id", true)
    );
    Assert.assertSame(replacementFailure, thrown);
    Assert.assertTrue(ImmutableList.copyOf(thrown.getSuppressed()).contains(rollbackFailure));
    Assert.assertSame(nextSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());

    Assert.assertTrue(manager.suspendOrResumeSupervisor("id", false));
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertFalse(manager.suspendOrResumeSupervisor("id", false));
    EasyMock.verify(oldSupervisor, restoredSupervisor, replacementSupervisor);
  }

  @Test
  public void testReplacementErrorCleansUpRollsBackAndRestoresPreviousRuntime()
  {
    final NoClassDefFoundError createError = new NoClassDefFoundError("missing extension class");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor,
        restoredSupervisor
    );
    previousSpec.suspendedSpec = new TransitionSupervisorSpec("id", true, "suspended", oldSupervisor)
    {
      @Override
      public Supervisor createSupervisor()
      {
        throw createError;
      }
    };
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andReturn(null);
    restoredSupervisor.start();
    EasyMock.replay(oldSupervisor, restoredSupervisor);

    Assert.assertSame(
        createError,
        Assert.assertThrows(NoClassDefFoundError.class, () -> manager.suspendOrResumeSupervisor("id", true))
    );
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    Assert.assertSame(previousSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, restoredSupervisor);
  }

  @Test
  public void testSuccessfulStartIsAcceptanceBoundaryWithoutHealthCheck()
  {
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec("id", false, "running", oldSupervisor);
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec("id", true, "suspended", replacementSupervisor);
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(null);
    // Returning from start represents registration of any asynchronous initialization/retry work.
    replacementSupervisor.start();
    EasyMock.replay(oldSupervisor, replacementSupervisor);

    Assert.assertTrue(manager.suspendOrResumeSupervisor("id", true));
    Assert.assertSame(nextSpec, metadata.latest.get("id"));
    Assert.assertSame(nextSpec, manager.getSupervisorSpec("id").get());
    EasyMock.verify(oldSupervisor, replacementSupervisor);
  }

  @Test
  public void testReplacementAutoscalerStartAndCleanupFailuresRemainSecondaryToRecreationFailure()
  {
    final RuntimeException startFailure = new RuntimeException("autoscaler start failed");
    final RuntimeException cleanupFailure = new RuntimeException("cleanup failed");
    final RuntimeException restorationFailure = new RuntimeException("restoration failed");
    final TestMetadataSupervisorManager metadata = new TestMetadataSupervisorManager();
    final Supervisor oldSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor restoredSupervisor = EasyMock.createMock(Supervisor.class);
    final Supervisor replacementSupervisor = EasyMock.createMock(Supervisor.class);
    final SupervisorTaskAutoScaler replacementAutoscaler = EasyMock.createMock(SupervisorTaskAutoScaler.class);
    final TransitionSupervisorSpec previousSpec = new TransitionSupervisorSpec(
        "id",
        false,
        "running",
        oldSupervisor,
        restoredSupervisor
    );
    final TransitionSupervisorSpec nextSpec = new TransitionSupervisorSpec(
        "id",
        true,
        "suspended",
        replacementSupervisor
    );
    previousSpec.suspendedSpec = nextSpec;
    startManager(metadata, previousSpec, oldSupervisor, null);

    oldSupervisor.stop(true);
    EasyMock.expect(replacementSupervisor.createAutoscaler(nextSpec)).andReturn(replacementAutoscaler);
    replacementSupervisor.start();
    replacementAutoscaler.start();
    EasyMock.expectLastCall().andThrow(startFailure);
    replacementAutoscaler.stop();
    EasyMock.expectLastCall().andThrow(cleanupFailure);
    replacementSupervisor.stop(true);
    EasyMock.expect(restoredSupervisor.createAutoscaler(previousSpec)).andThrow(restorationFailure);
    restoredSupervisor.stop(true);
    EasyMock.replay(oldSupervisor, restoredSupervisor, replacementSupervisor, replacementAutoscaler);

    final RuntimeException thrown = Assert.assertThrows(
        RuntimeException.class,
        () -> manager.suspendOrResumeSupervisor("id", true)
    );
    Assert.assertSame(startFailure, thrown);
    Assert.assertEquals(2, thrown.getSuppressed().length);
    Assert.assertSame(cleanupFailure, thrown.getSuppressed()[0]);
    Assert.assertSame(restorationFailure, thrown.getSuppressed()[1]);
    Assert.assertSame(previousSpec, metadata.latest.get("id"));
    // Total restoration failure removes the stale entry, so API readers can observe a 404 until it is recreated.
    Assert.assertFalse(manager.getSupervisorSpec("id").isPresent());
    assertTransitionAlert(
        "Failed to restore previous runtime for supervisor [id], re-submit the previous supervisor spec with "
        + "POST /supervisor to recreate the runtime",
        "restoring the previous runtime"
    );
    EasyMock.verify(oldSupervisor, restoredSupervisor, replacementSupervisor, replacementAutoscaler);
  }

  @Test
  public void testGetActiveSupervisorIdForDatasourceWithAppendLock()
  {
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(Collections.emptyMap());

    NoopSupervisorSpec noopSupervisorSpec = new NoopSupervisorSpec("noop", ImmutableList.of("noopDS"));
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    SeekableStreamSupervisorSpec suspendedSpec = EasyMock.createNiceMock(SeekableStreamSupervisorSpec.class);
    Supervisor suspendedSupervisor = EasyMock.createNiceMock(SeekableStreamSupervisor.class);
    EasyMock.expect(suspendedSpec.getId()).andReturn("suspendedSpec").anyTimes();
    EasyMock.expect(suspendedSpec.isSuspended()).andReturn(true).anyTimes();
    EasyMock.expect(suspendedSpec.getDataSources()).andReturn(ImmutableList.of("suspendedDS")).anyTimes();
    EasyMock.expect(suspendedSpec.createSupervisor()).andReturn(suspendedSupervisor).anyTimes();
    EasyMock.expect(suspendedSpec.createAutoscaler(suspendedSupervisor)).andReturn(null).anyTimes();
    EasyMock.expect(suspendedSpec.getContext()).andReturn(null).anyTimes();
    EasyMock.replay(suspendedSpec, suspendedSupervisor);
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    SeekableStreamSupervisorSpec activeSpec = EasyMock.createNiceMock(SeekableStreamSupervisorSpec.class);
    Supervisor activeSupervisor = EasyMock.createNiceMock(SeekableStreamSupervisor.class);
    EasyMock.expect(activeSpec.getId()).andReturn("activeSpec").anyTimes();
    EasyMock.expect(activeSpec.isSuspended()).andReturn(false).anyTimes();
    EasyMock.expect(activeSpec.getDataSources()).andReturn(ImmutableList.of("activeDS")).anyTimes();
    EasyMock.expect(activeSpec.createSupervisor()).andReturn(activeSupervisor).anyTimes();
    EasyMock.expect(activeSpec.createAutoscaler(activeSupervisor)).andReturn(null).anyTimes();
    EasyMock.expect(activeSpec.getContext()).andReturn(null).anyTimes();
    EasyMock.replay(activeSpec, activeSupervisor);
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    SeekableStreamSupervisorSpec activeSpecWithConcurrentLocks = EasyMock.createNiceMock(SeekableStreamSupervisorSpec.class);
    Supervisor activeSupervisorWithConcurrentLocks = EasyMock.createNiceMock(SeekableStreamSupervisor.class);
    EasyMock.expect(activeSpecWithConcurrentLocks.getId()).andReturn("activeSpecWithConcurrentLocks").anyTimes();
    EasyMock.expect(activeSpecWithConcurrentLocks.isSuspended()).andReturn(false).anyTimes();
    EasyMock.expect(activeSpecWithConcurrentLocks.getDataSources())
            .andReturn(ImmutableList.of("activeConcurrentLocksDS")).anyTimes();
    EasyMock.expect(activeSpecWithConcurrentLocks.createSupervisor())
            .andReturn(activeSupervisorWithConcurrentLocks).anyTimes();
    EasyMock.expect(activeSpecWithConcurrentLocks.createAutoscaler(activeSupervisorWithConcurrentLocks))
            .andReturn(null).anyTimes();
    EasyMock.expect(activeSpecWithConcurrentLocks.getContext())
            .andReturn(ImmutableMap.of(Tasks.USE_CONCURRENT_LOCKS, true)).anyTimes();
    EasyMock.replay(activeSpecWithConcurrentLocks, activeSupervisorWithConcurrentLocks);
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    SeekableStreamSupervisorSpec activeAppendSpec = EasyMock.createNiceMock(SeekableStreamSupervisorSpec.class);
    Supervisor activeAppendSupervisor = EasyMock.createNiceMock(SeekableStreamSupervisor.class);
    EasyMock.expect(activeAppendSpec.getId()).andReturn("activeAppendSpec").anyTimes();
    EasyMock.expect(activeAppendSpec.isSuspended()).andReturn(false).anyTimes();
    EasyMock.expect(activeAppendSpec.getDataSources()).andReturn(ImmutableList.of("activeAppendDS")).anyTimes();
    EasyMock.expect(activeAppendSpec.createSupervisor()).andReturn(activeAppendSupervisor).anyTimes();
    EasyMock.expect(activeAppendSpec.createAutoscaler(activeAppendSupervisor)).andReturn(null).anyTimes();
    EasyMock.expect(activeAppendSpec.getContext()).andReturn(ImmutableMap.of(
        Tasks.TASK_LOCK_TYPE,
        TaskLockType.APPEND.name()
    )).anyTimes();
    EasyMock.replay(activeAppendSpec, activeAppendSupervisor);
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    // A supervisor with useConcurrentLocks set to false explicitly must not use an append lock
    SeekableStreamSupervisorSpec specWithUseConcurrentLocksFalse = EasyMock.createNiceMock(SeekableStreamSupervisorSpec.class);
    Supervisor supervisorWithUseConcurrentLocksFalse = EasyMock.createNiceMock(SeekableStreamSupervisor.class);
    EasyMock.expect(specWithUseConcurrentLocksFalse.getId()).andReturn("useConcurrentLocksFalse").anyTimes();
    EasyMock.expect(specWithUseConcurrentLocksFalse.isSuspended()).andReturn(false).anyTimes();
    EasyMock.expect(specWithUseConcurrentLocksFalse.getDataSources())
            .andReturn(ImmutableList.of("dsWithuseConcurrentLocksFalse")).anyTimes();
    EasyMock.expect(specWithUseConcurrentLocksFalse.createSupervisor()).andReturn(supervisorWithUseConcurrentLocksFalse).anyTimes();
    EasyMock.expect(specWithUseConcurrentLocksFalse.createAutoscaler(supervisorWithUseConcurrentLocksFalse))
            .andReturn(null).anyTimes();
    EasyMock.expect(specWithUseConcurrentLocksFalse.getContext()).andReturn(ImmutableMap.of(
        Tasks.USE_CONCURRENT_LOCKS,
        false,
        Tasks.TASK_LOCK_TYPE,
        TaskLockType.APPEND.name()
    )).anyTimes();
    EasyMock.replay(specWithUseConcurrentLocksFalse, supervisorWithUseConcurrentLocksFalse);
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    replayAll();
    manager.start();

    Assert.assertFalse(manager.getActiveSupervisorIdForDatasourceWithAppendLock("nonExistent").isPresent());

    manager.createOrUpdateAndStartSupervisor(noopSupervisorSpec);
    Assert.assertFalse(manager.getActiveSupervisorIdForDatasourceWithAppendLock("noopDS").isPresent());

    manager.createOrUpdateAndStartSupervisor(suspendedSpec);
    Assert.assertFalse(manager.getActiveSupervisorIdForDatasourceWithAppendLock("suspendedDS").isPresent());

    manager.createOrUpdateAndStartSupervisor(activeSpec);
    Assert.assertFalse(manager.getActiveSupervisorIdForDatasourceWithAppendLock("activeDS").isPresent());

    manager.createOrUpdateAndStartSupervisor(activeAppendSpec);
    Assert.assertTrue(manager.getActiveSupervisorIdForDatasourceWithAppendLock("activeAppendDS").isPresent());

    manager.createOrUpdateAndStartSupervisor(activeSpecWithConcurrentLocks);
    Assert.assertTrue(manager.getActiveSupervisorIdForDatasourceWithAppendLock("activeConcurrentLocksDS").isPresent());

    manager.createOrUpdateAndStartSupervisor(specWithUseConcurrentLocksFalse);
    Assert.assertFalse(
        manager.getActiveSupervisorIdForDatasourceWithAppendLock("dsWithUseConcurrentLocksFalse").isPresent()
    );

    verifyAll();
  }

  @Test
  public void testRegisterUpgradedPendingSegmentOnSupervisor()
  {
    EasyMock.expect(metadataSupervisorManager.getLatest()).andReturn(Collections.emptyMap());

    NoopSupervisorSpec noopSpec = new NoopSupervisorSpec("noop", ImmutableList.of("noopDS"));
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());

    SeekableStreamSupervisorSpec streamingSpec = EasyMock.createNiceMock(SeekableStreamSupervisorSpec.class);
    SeekableStreamSupervisor streamSupervisor = EasyMock.createNiceMock(SeekableStreamSupervisor.class);
    streamSupervisor.registerNewVersionOfPendingSegment(EasyMock.anyObject());
    EasyMock.expectLastCall().once();
    EasyMock.expect(streamingSpec.getId()).andReturn("sss").anyTimes();
    EasyMock.expect(streamingSpec.isSuspended()).andReturn(false).anyTimes();
    EasyMock.expect(streamingSpec.getDataSources()).andReturn(ImmutableList.of("DS")).anyTimes();
    EasyMock.expect(streamingSpec.createSupervisor()).andReturn(streamSupervisor).anyTimes();
    EasyMock.expect(streamingSpec.createAutoscaler(streamSupervisor)).andReturn(null).anyTimes();
    EasyMock.expect(streamingSpec.getContext()).andReturn(null).anyTimes();
    EasyMock.replay(streamingSpec, streamSupervisor);
    metadataSupervisorManager.insert(EasyMock.anyString(), EasyMock.anyObject());
    EasyMock.expectLastCall().once();

    replayAll();

    final PendingSegmentRecord pendingSegment = PendingSegmentRecord.create(
        new SegmentIdWithShardSpec(
            "DS",
            Intervals.ETERNITY,
            "version",
            new NumberedShardSpec(0, 0)
        ),
        "sequenceName",
        "prevSegmentId",
        "upgradedFromSegmentId",
        "taskAllocatorId"
    );
    manager.start();

    manager.createOrUpdateAndStartSupervisor(noopSpec);
    Assert.assertFalse(manager.registerUpgradedPendingSegmentOnSupervisor("noop", pendingSegment));

    manager.createOrUpdateAndStartSupervisor(streamingSpec);
    Assert.assertTrue(manager.registerUpgradedPendingSegmentOnSupervisor("sss", pendingSegment));

    verifyAll();
  }

  private static class TestSupervisorSpec implements SupervisorSpec
  {
    private final String id;
    private final Supervisor supervisor;
    private final boolean suspended;
    private final Supervisor suspendedSupervisor;


    TestSupervisorSpec(String id, Supervisor supervisor)
    {
      this(id, supervisor, false, null);
    }

    TestSupervisorSpec(String id, Supervisor supervisor, boolean suspended, Supervisor suspendedSupervisor)
    {
      this.id = id;
      this.supervisor = supervisor;
      this.suspended = suspended;
      this.suspendedSupervisor = suspendedSupervisor;
    }

    @Override
    public SupervisorSpec createSuspendedSpec()
    {
      return new TestSupervisorSpec(id, suspendedSupervisor, true, supervisor);
    }

    @Override
    public SupervisorSpec createRunningSpec()
    {
      return new TestSupervisorSpec(id, suspendedSupervisor, false, supervisor);
    }

    @Override
    public String getId()
    {
      return id;
    }

    @Override
    public Supervisor createSupervisor()
    {
      return supervisor;
    }

    @Override
    public boolean isSuspended()
    {
      return suspended;
    }

    @Override
    public String getType()
    {
      return "TestSupervisorSpec";
    }

    @Override
    public String getSource()
    {
      return null;
    }

    @Override
    public List<String> getDataSources()
    {
      return new ArrayList<>();
    }
  }

  private void assertTransitionAlert(String description, String stage)
  {
    final List<AlertEvent> alerts = emitter.getAlerts();
    Assert.assertEquals(1, alerts.size());
    final AlertEvent alert = alerts.get(0);
    Assert.assertEquals(description, alert.getDescription());
    Assert.assertEquals("id", alert.getDataMap().get("supervisorId"));
    Assert.assertEquals(stage, alert.getDataMap().get("stage"));
    Assert.assertFalse(alert.getDataMap().containsKey("runtimeSuspended"));
    Assert.assertFalse(alert.getDataMap().containsKey("metadataSuspended"));
  }

  private void startManager(
      TestMetadataSupervisorManager metadata,
      TransitionSupervisorSpec spec,
      Supervisor initialSupervisor,
      SupervisorTaskAutoScaler initialAutoscaler
  )
  {
    metadata.latest.put(spec.getId(), spec);
    EasyMock.expect(initialSupervisor.createAutoscaler(spec)).andReturn(initialAutoscaler);
    initialSupervisor.start();
    if (initialAutoscaler != null) {
      initialAutoscaler.start();
      EasyMock.replay(initialSupervisor, initialAutoscaler);
    } else {
      EasyMock.replay(initialSupervisor);
    }

    manager = new SupervisorManager(MAPPER, metadata);
    manager.start();

    if (initialAutoscaler != null) {
      EasyMock.verify(initialSupervisor, initialAutoscaler);
      EasyMock.reset(initialSupervisor, initialAutoscaler);
    } else {
      EasyMock.verify(initialSupervisor);
      EasyMock.reset(initialSupervisor);
    }
    metadata.inserts.clear();
    metadata.reads = 0;
  }

  private static class TransitionSupervisorSpec implements SupervisorSpec
  {
    private final String id;
    private final boolean suspended;
    private final String config;
    private final Supervisor[] supervisorInstances;
    private int nextSupervisorInstance;
    private TransitionSupervisorSpec suspendedSpec;
    private TransitionSupervisorSpec runningSpec;
    private RuntimeException serializationFailure;

    TransitionSupervisorSpec(String id, boolean suspended, String config, Supervisor... supervisorInstances)
    {
      this.id = id;
      this.suspended = suspended;
      this.config = config;
      this.supervisorInstances = supervisorInstances;
    }

    @Override
    public SupervisorSpec createSuspendedSpec()
    {
      return suspendedSpec;
    }

    @Override
    public SupervisorSpec createRunningSpec()
    {
      return runningSpec;
    }

    @Override
    @JsonProperty
    public String getId()
    {
      return id;
    }

    @Override
    public Supervisor createSupervisor()
    {
      return supervisorInstances[Math.min(nextSupervisorInstance++, supervisorInstances.length - 1)];
    }

    @Override
    @JsonProperty
    public boolean isSuspended()
    {
      return suspended;
    }

    @JsonProperty
    public String getConfig()
    {
      if (serializationFailure != null) {
        throw serializationFailure;
      }
      return config;
    }

    @Override
    public String getType()
    {
      return "transition-test";
    }

    @Override
    public String getSource()
    {
      return null;
    }

    @Override
    public List<String> getDataSources()
    {
      return ImmutableList.of("datasource");
    }
  }

  private static class TestMetadataSupervisorManager implements MetadataSupervisorManager
  {
    private final Map<String, SupervisorSpec> latest = new HashMap<>();
    private final List<SupervisorSpec> inserts = new ArrayList<>();
    private final Deque<InsertBehavior> insertBehaviors = new ArrayDeque<>();
    private final Deque<RuntimeException> readFailures = new ArrayDeque<>();
    private final List<String> events;
    private int reads;

    TestMetadataSupervisorManager()
    {
      this(new ArrayList<>());
    }

    TestMetadataSupervisorManager(List<String> events)
    {
      this.events = events;
    }

    void addInsertSuccess()
    {
      insertBehaviors.add(new InsertBehavior(true, null));
    }

    void addInsertFailure(boolean commit, RuntimeException exception)
    {
      insertBehaviors.add(new InsertBehavior(commit, exception));
    }

    void setLatest(String id, SupervisorSpec spec)
    {
      latest.put(id, spec);
    }

    @Override
    public void start()
    {
      // No-op.
    }

    @Override
    public void insert(String id, SupervisorSpec spec)
    {
      inserts.add(spec);
      events.add("insert:" + (spec.isSuspended() ? "suspended" : "running"));
      final InsertBehavior behavior = insertBehaviors.isEmpty()
                                      ? new InsertBehavior(true, null)
                                      : insertBehaviors.remove();
      if (behavior.commit) {
        latest.put(id, spec);
      }
      if (behavior.exception != null) {
        throw behavior.exception;
      }
    }

    @Override
    public Map<String, List<VersionedSupervisorSpec>> getAll()
    {
      return Collections.emptyMap();
    }

    @Override
    public List<VersionedSupervisorSpec> getAllForId(String id, Integer limit)
    {
      reads++;
      if (!readFailures.isEmpty()) {
        throw readFailures.remove();
      }
      final SupervisorSpec spec = latest.get(id);
      return spec == null
             ? Collections.emptyList()
             : Collections.singletonList(new VersionedSupervisorSpec(spec, "version"));
    }

    @Override
    public Map<String, SupervisorSpec> getLatest()
    {
      reads++;
      if (!readFailures.isEmpty()) {
        throw readFailures.remove();
      }
      return new HashMap<>(latest);
    }

    @Override
    public Map<String, SupervisorSpec> getLatestActiveOnly()
    {
      return Collections.emptyMap();
    }

    @Override
    public Map<String, SupervisorSpec> getLatestTerminatedOnly()
    {
      return Collections.emptyMap();
    }

    @Override
    public int removeTerminatedSupervisorsOlderThan(long timestamp)
    {
      return 0;
    }
  }

  private static class InsertBehavior
  {
    private final boolean commit;
    private final RuntimeException exception;

    InsertBehavior(boolean commit, RuntimeException exception)
    {
      this.commit = commit;
      this.exception = exception;
    }
  }
}
