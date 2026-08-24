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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.inject.Inject;
import org.apache.druid.common.guava.FutureUtils;
import org.apache.druid.error.DruidException;
import org.apache.druid.guice.annotations.Json;
import org.apache.druid.indexing.common.TaskLockType;
import org.apache.druid.indexing.common.task.Tasks;
import org.apache.druid.indexing.overlord.DataSourceMetadata;
import org.apache.druid.indexing.overlord.supervisor.autoscaler.SupervisorTaskAutoScaler;
import org.apache.druid.indexing.seekablestream.supervisor.SeekableStreamSupervisor;
import org.apache.druid.indexing.seekablestream.supervisor.SeekableStreamSupervisorSpec;
import org.apache.druid.java.util.common.Pair;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.common.lifecycle.LifecycleStart;
import org.apache.druid.java.util.common.lifecycle.LifecycleStop;
import org.apache.druid.java.util.emitter.EmittingLogger;
import org.apache.druid.metadata.MetadataSupervisorManager;
import org.apache.druid.metadata.PendingSegmentRecord;
import org.apache.druid.query.QueryContexts;
import org.apache.druid.segment.incremental.ParseExceptionReport;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

/**
 * Manages the creation and lifetime of {@link Supervisor}.
 * <p>
 * Metadata repair and compensation use unconditional writes because {@link MetadataSupervisorManager} does not expose
 * a conditional-write API. Tombstone checks are therefore best effort: a concurrent metadata update can occur between
 * a check and the following insert and can be superseded by that insert. Strong concurrency guarantees require a
 * revision-aware conditional write in the metadata layer.
 */
public class SupervisorManager
{
  private static final EmittingLogger log = new EmittingLogger(SupervisorManager.class);

  private final MetadataSupervisorManager metadataSupervisorManager;
  private final ConcurrentHashMap<String, Pair<Supervisor, SupervisorSpec>> supervisors = new ConcurrentHashMap<>();
  // SupervisorTaskAutoScaler could be null
  private final ConcurrentHashMap<String, SupervisorTaskAutoScaler> autoscalers = new ConcurrentHashMap<>();
  private final Object lock = new Object();

  private volatile boolean started = false;
  private final ObjectMapper jsonMapper;

  @Inject
  public SupervisorManager(@Json ObjectMapper jsonMapper, MetadataSupervisorManager metadataSupervisorManager)
  {
    this.jsonMapper = jsonMapper;
    this.metadataSupervisorManager = metadataSupervisorManager;
  }

  public MetadataSupervisorManager getMetadataSupervisorManager()
  {
    return metadataSupervisorManager;
  }

  public Set<String> getSupervisorIds()
  {
    return supervisors.keySet();
  }

  /**
   * @param datasource Datasource to find active supervisor id with append lock for.
   * @return An optional with the active appending supervisor id if it exists.
   */
  public Optional<String> getActiveSupervisorIdForDatasourceWithAppendLock(String datasource)
  {
    for (Map.Entry<String, Pair<Supervisor, SupervisorSpec>> entry : supervisors.entrySet()) {
      final String supervisorId = entry.getKey();
      final Supervisor supervisor = entry.getValue().lhs;
      final SupervisorSpec supervisorSpec = entry.getValue().rhs;

      boolean hasAppendLock = Tasks.DEFAULT_USE_CONCURRENT_LOCKS;
      if (supervisorSpec instanceof SeekableStreamSupervisorSpec) {
        SeekableStreamSupervisorSpec seekableStreamSupervisorSpec = (SeekableStreamSupervisorSpec) supervisorSpec;
        Map<String, Object> context = seekableStreamSupervisorSpec.getContext();
        if (context != null) {
          Boolean useConcurrentLocks = QueryContexts.getAsBoolean(
              Tasks.USE_CONCURRENT_LOCKS,
              context.get(Tasks.USE_CONCURRENT_LOCKS)
          );
          if (useConcurrentLocks == null) {
            TaskLockType taskLockType = QueryContexts.getAsEnum(
                Tasks.TASK_LOCK_TYPE,
                context.get(Tasks.TASK_LOCK_TYPE),
                TaskLockType.class
            );
            if (taskLockType == null) {
              hasAppendLock = Tasks.DEFAULT_USE_CONCURRENT_LOCKS;
            } else if (taskLockType == TaskLockType.APPEND) {
              hasAppendLock = true;
            } else {
              hasAppendLock = false;
            }
          } else {
            hasAppendLock = useConcurrentLocks;
          }
        }
      }

      if (supervisor instanceof SeekableStreamSupervisor
          && !supervisorSpec.isSuspended()
          && supervisorSpec.getDataSources().contains(datasource)
          && (hasAppendLock)) {
        return Optional.of(supervisorId);
      }
    }

    return Optional.absent();
  }

  public Optional<SupervisorSpec> getSupervisorSpec(String id)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    return supervisor == null ? Optional.absent() : Optional.fromNullable(supervisor.rhs);
  }

  public Optional<SupervisorStateManager.State> getSupervisorState(String id)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    return supervisor == null ? Optional.absent() : Optional.fromNullable(supervisor.lhs.getState());
  }

  public boolean handoffTaskGroupsEarly(String id, List<Integer> taskGroupIds)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    if (supervisor == null || supervisor.lhs == null) {
      return false;
    }
    final StreamSupervisor streamSupervisor = requireStreamSupervisor(id, "handoff");
    streamSupervisor.handoffTaskGroupsEarly(taskGroupIds);
    return true;
  }

  /**
   * Creates or updates a supervisor and then starts it.
   * If no change has been made to the supervisor spec, it is only restarted.
   *
   * @return true if the supervisor was updated, false otherwise
   */
  public boolean createOrUpdateAndStartSupervisor(SupervisorSpec spec)
  {
    Preconditions.checkState(started, "SupervisorManager not started");
    Preconditions.checkNotNull(spec, "spec");
    Preconditions.checkNotNull(spec.getId(), "spec.getId()");
    Preconditions.checkNotNull(spec.getDataSources(), "spec.getDatasources()");

    synchronized (lock) {
      Preconditions.checkState(started, "SupervisorManager not started");
      final boolean shouldUpdateSpec = shouldUpdateSupervisor(spec);
      SupervisorSpec existingSpec = possiblyStopAndRemoveSupervisorInternal(spec.getId(), false);
      if (existingSpec != null) {
        spec.merge(existingSpec);
      }
      createAndStartSupervisorInternal(spec, shouldUpdateSpec);
      return shouldUpdateSpec;
    }
  }

  /**
   * Checks whether the submitted SupervisorSpec differs from the current spec in SupervisorManager's supervisor list.
   * This is used in SupervisorResource specPost to determine whether the Supervisor needs to be restarted
   *
   * @param spec The spec submitted
   * @return boolean - true only if the spec has been modified, false otherwise
   */
  public boolean shouldUpdateSupervisor(SupervisorSpec spec)
  {
    Preconditions.checkState(started, "SupervisorManager not started");
    Preconditions.checkNotNull(spec, "spec");
    Preconditions.checkNotNull(spec.getId(), "spec.getId()");
    Preconditions.checkNotNull(spec.getDataSources(), "spec.getDatasources()");
    synchronized (lock) {
      Preconditions.checkState(started, "SupervisorManager not started");
      try {
        byte[] specAsBytes = jsonMapper.writeValueAsBytes(spec);
        Pair<Supervisor, SupervisorSpec> currentSupervisor = supervisors.get(spec.getId());
        if (currentSupervisor == null || currentSupervisor.rhs == null) {
          return true;
        } else if (Arrays.equals(specAsBytes, jsonMapper.writeValueAsBytes(currentSupervisor.rhs))) {
          return false;
        } else {
          // The spec bytes are different, so we need to check if the update is allowed
          currentSupervisor.rhs.validateSpecUpdateTo(spec);
          return true;
        }
      }
      catch (JsonProcessingException ex) {
        log.warn("Failed to write spec as bytes for spec_id[%s]", spec.getId());
      }
    }
    return true;
  }

  public boolean stopAndRemoveSupervisor(String id)
  {
    Preconditions.checkState(started, "SupervisorManager not started");
    Preconditions.checkNotNull(id, "id");

    synchronized (lock) {
      Preconditions.checkState(started, "SupervisorManager not started");
      return possiblyStopAndRemoveSupervisorInternal(id, true) != null;
    }
  }

  public boolean suspendOrResumeSupervisor(String id, boolean suspend)
  {
    Preconditions.checkState(started, "SupervisorManager not started");
    Preconditions.checkNotNull(id, "id");

    synchronized (lock) {
      Preconditions.checkState(started, "SupervisorManager not started");
      return possiblySuspendOrResumeSupervisorInternal(id, suspend);
    }
  }

  @LifecycleStart
  public void start()
  {
    Preconditions.checkState(!started, "SupervisorManager already started");
    log.info("Loading stored supervisors from database");

    synchronized (lock) {
      Map<String, SupervisorSpec> supervisors = metadataSupervisorManager.getLatest();
      for (Map.Entry<String, SupervisorSpec> supervisor : supervisors.entrySet()) {
        final SupervisorSpec spec = supervisor.getValue();
        if (!(spec instanceof NoopSupervisorSpec)) {
          try {
            createAndStartSupervisorInternal(spec, false);
          }
          catch (Exception ex) {
            log.error(ex, "Failed to start supervisor: id [%s]", spec.getId());
          }
        }
      }

      started = true;
    }
  }

  @LifecycleStop
  public void stop()
  {
    Preconditions.checkState(started, "SupervisorManager not started");
    List<ListenableFuture<Void>> stopFutures = new ArrayList<>();
    synchronized (lock) {
      log.info("Stopping [%d] supervisors", supervisors.keySet().size());
      for (String id : supervisors.keySet()) {
        try {
          stopFutures.add(supervisors.get(id).lhs.stopAsync());
          SupervisorTaskAutoScaler autoscaler = autoscalers.get(id);
          if (autoscaler != null) {
            autoscaler.stop();
          }
        }
        catch (Exception e) {
          log.warn(e, "Caught exception while stopping supervisor [%s]", id);
        }
      }
      log.info("Waiting for [%d] supervisors to shutdown", stopFutures.size());
      try {
        FutureUtils.coalesce(stopFutures).get();
      }
      catch (Exception e) {
        log.warn(
            e,
            "Stopped [%d] out of [%d] supervisors. Remaining supervisors will be killed.",
            stopFutures.stream().filter(Future::isDone).count(),
            stopFutures.size()
        );
      }
      supervisors.clear();
      autoscalers.clear();
      started = false;
    }

    log.info("SupervisorManager stopped.");
  }

  public List<VersionedSupervisorSpec> getSupervisorHistoryForId(String id, @Nullable Integer limit)
      throws IllegalArgumentException
  {
    return metadataSupervisorManager.getAllForId(id, limit);
  }

  public Map<String, List<VersionedSupervisorSpec>> getSupervisorHistory()
  {
    return metadataSupervisorManager.getAll();
  }

  public Optional<SupervisorReport> getSupervisorStatus(String id)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    return supervisor == null ? Optional.absent() : Optional.fromNullable(supervisor.lhs.getStatus());
  }

  public Optional<Map<String, Map<String, Object>>> getSupervisorStats(String id)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    return supervisor == null ? Optional.absent() : Optional.fromNullable(supervisor.lhs.getStats());
  }

  public Optional<List<ParseExceptionReport>> getSupervisorParseErrors(String id)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    return supervisor == null ? Optional.absent() : Optional.fromNullable(supervisor.lhs.getParseErrors());
  }

  public Optional<Boolean> isSupervisorHealthy(String id)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
    return supervisor == null ? Optional.absent() : Optional.fromNullable(supervisor.lhs.isHealthy());
  }

  public boolean resetSupervisor(String id, @Nullable DataSourceMetadata resetDataSourceMetadata)
  {
    Preconditions.checkState(started, "SupervisorManager not started");
    Preconditions.checkNotNull(id, "id");

    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);

    if (supervisor == null) {
      return false;
    }

    final StreamSupervisor streamSupervisor = requireStreamSupervisor(id, "reset");
    if (resetDataSourceMetadata == null) {
      streamSupervisor.reset(null);
    } else {
      streamSupervisor.resetOffsets(resetDataSourceMetadata);
    }
    SupervisorTaskAutoScaler autoscaler = autoscalers.get(id);
    if (autoscaler != null) {
      autoscaler.reset();
    }
    return true;
  }

  public boolean checkPointDataSourceMetadata(
      String supervisorId,
      int taskGroupId,
      DataSourceMetadata previousDataSourceMetadata
  )
  {
    try {
      Preconditions.checkState(started, "SupervisorManager not started");
      Preconditions.checkNotNull(supervisorId, "supervisorId cannot be null");

      Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(supervisorId);

      Preconditions.checkNotNull(supervisor, "supervisor could not be found");

      final StreamSupervisor streamSupervisor = requireStreamSupervisor(supervisorId, "checkPoint");
      streamSupervisor.checkpoint(taskGroupId, previousDataSourceMetadata);
      return true;
    }
    catch (Exception e) {
      log.error(e, "Checkpoint request failed");
    }
    return false;
  }

  /**
   * Registers a new version of the given pending segment on a supervisor. This
   * allows the supervisor to include the pending segment in queries fired against
   * that segment version.
   */
  public boolean registerUpgradedPendingSegmentOnSupervisor(
      String supervisorId,
      PendingSegmentRecord upgradedPendingSegment
  )
  {
    try {
      Preconditions.checkNotNull(supervisorId, "supervisorId cannot be null");
      Preconditions.checkNotNull(upgradedPendingSegment, "upgraded pending segment cannot be null");
      Preconditions.checkNotNull(upgradedPendingSegment.getTaskAllocatorId(), "taskAllocatorId cannot be null");
      Preconditions.checkNotNull(
          upgradedPendingSegment.getUpgradedFromSegmentId(),
          "upgradedFromSegmentId cannot be null"
      );

      Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(supervisorId);
      Preconditions.checkNotNull(supervisor, "supervisor could not be found");
      if (!(supervisor.lhs instanceof SeekableStreamSupervisor)) {
        return false;
      }

      SeekableStreamSupervisor<?, ?, ?> seekableStreamSupervisor = (SeekableStreamSupervisor<?, ?, ?>) supervisor.lhs;
      seekableStreamSupervisor.registerNewVersionOfPendingSegment(upgradedPendingSegment);
      return true;
    }
    catch (Exception e) {
      log.error(
          e,
          "Failed to upgrade pending segment[%s] to new pending segment[%s] on Supervisor[%s].",
          upgradedPendingSegment.getUpgradedFromSegmentId(),
          upgradedPendingSegment.getId().getVersion(),
          supervisorId
      );
    }
    return false;
  }


  /**
   * Stops a supervisor with a given id and then removes it from the list.
   * <p/>
   * Caller should have acquired [lock] before invoking this method to avoid contention with other threads that may be
   * starting, stopping, suspending and resuming supervisors.
   *
   * @return reference to existing supervisor, if exists and was stopped, null if there was no supervisor with this id
   */
  @Nullable
  private SupervisorSpec possiblyStopAndRemoveSupervisorInternal(String id, boolean writeTombstone)
  {
    Pair<Supervisor, SupervisorSpec> pair = supervisors.get(id);
    if (pair == null || pair.rhs == null || pair.lhs == null) {
      return null;
    }

    if (writeTombstone) {
      metadataSupervisorManager.insert(
          id,
          new NoopSupervisorSpec(null, pair.rhs.getDataSources())
      ); // where NoopSupervisorSpec is a tombstone
    }
    pair.lhs.stop(true);
    supervisors.remove(id);

    SupervisorTaskAutoScaler autoscaler = autoscalers.get(id);
    if (autoscaler != null) {
      autoscaler.stop();
      autoscalers.remove(id);
    }

    return pair.rhs;
  }

  /**
   * Suspend or resume a supervisor with a given id.
   * <p/>
   * Caller should have acquired [lock] before invoking this method to avoid contention with other threads that may be
   * starting, stopping, suspending and resuming supervisors.
   *
   * @return true if the supervisor was suspended or resumed, or if metadata was repaired to match an already applied
   * runtime state, false if the supervisor does not exist, already has the requested state with matching metadata, or
   * metadata repair could not be completed
   */
  private boolean possiblySuspendOrResumeSupervisorInternal(String id, boolean suspend)
  {
    final Pair<Supervisor, SupervisorSpec> previousPair = supervisors.get(id);
    if (previousPair == null) {
      return false;
    }
    if (previousPair.rhs.isSuspended() == suspend) {
      return repairMetadataForAppliedTransitionIfNeeded(id, previousPair.rhs);
    }

    final SupervisorSpec previousSpec = previousPair.rhs;
    final SupervisorSpec nextSpec = suspend ? previousSpec.createSuspendedSpec() : previousSpec.createRunningSpec();
    Preconditions.checkState(
        id.equals(nextSpec.getId()),
        "Suspended or running supervisor spec must preserve id [%s], but generated id [%s]",
        id,
        nextSpec.getId()
    );

    persistTransitionSpec(id, previousSpec, nextSpec);

    final SupervisorTaskAutoScaler previousAutoscaler = autoscalers.get(id);
    try {
      // keep both entries visible until all stop calls have returned successfully
      if (previousAutoscaler != null) {
        previousAutoscaler.stop();
      }
      previousPair.lhs.stop(true);
    }
    catch (Exception | LinkageError stopException) {
      compensateMetadata(id, previousSpec, stopException, "stopping the previous runtime");
      emitTransitionAlert(
          stopException,
          id,
          "stopping the previous runtime",
          "Failed to stop previous runtime for supervisor [%s], runtime state is unverified and the existing "
          + "supervisor entry remains registered",
          id
      );
      throw asUnchecked(stopException);
    }

    final SupervisorRuntime replacementRuntime = new SupervisorRuntime();
    try {
      createAndStartSupervisorRuntime(nextSpec, replacementRuntime);
      registerSupervisorRuntime(nextSpec, replacementRuntime);
      return true;
    }
    catch (Exception | LinkageError recreationException) {
      cleanupRuntime(replacementRuntime, recreationException, "replacement", id);
      compensateMetadata(id, previousSpec, recreationException, "recreating the replacement runtime");
      restorePreviousRuntime(id, previousSpec, recreationException);
      throw asUnchecked(recreationException);
    }
  }

  /**
   * Repairs metadata when the requested state is already active in memory. This makes retries reconcile an ambiguous
   * prior metadata write without restarting a healthy runtime.
   */
  private boolean repairMetadataForAppliedTransitionIfNeeded(String id, SupervisorSpec runtimeSpec)
  {
    try {
      final SupervisorSpec latestSpec = getLatestMetadataSpec(id);
      if (latestSpec instanceof NoopSupervisorSpec) {
        warnTombstoneConflict(id, null, "checking an already applied supervisor transition");
        return false;
      }
      if (specsExactlyMatch(runtimeSpec, latestSpec)) {
        return false;
      }
      metadataSupervisorManager.insert(id, runtimeSpec);
      return true;
    }
    catch (Exception | LinkageError e) {
      log.error(
          e,
          "Unable to reconcile metadata for supervisor [%s], %s",
          id,
          repairInstruction(id, runtimeSpec)
      );
      return false;
    }
  }

  // persists the requested transition before touching the current runtime
  private void persistTransitionSpec(String id, SupervisorSpec previousSpec, SupervisorSpec nextSpec)
  {
    try {
      metadataSupervisorManager.insert(id, nextSpec);
    }
    catch (RuntimeException | LinkageError insertException) {
      final SupervisorSpec latestSpec = readLatestQuietly(id, insertException);
      final boolean transitionSpecIsLatest;
      final boolean previousSpecIsLatest;
      try {
        transitionSpecIsLatest = specsExactlyMatch(nextSpec, latestSpec);
        previousSpecIsLatest = !transitionSpecIsLatest && specsExactlyMatch(previousSpec, latestSpec);
      }
      catch (RuntimeException | LinkageError comparisonException) {
        addSuppressed(insertException, comparisonException);
        compensateMetadata(id, previousSpec, insertException, "persisting the transition spec");
        throw asUnchecked(insertException);
      }
      if (transitionSpecIsLatest) {
        log.warn(
            insertException,
            "Insert of transition spec [%s] reported failure, but readback confirmed it committed",
            id
        );
        return;
      }
      if (!previousSpecIsLatest) {
        if (latestSpec instanceof NoopSupervisorSpec) {
          warnTombstoneConflict(id, insertException, "persisting the transition spec");
        } else {
          compensateMetadata(id, previousSpec, insertException, "persisting the transition spec");
        }
      }
      throw asUnchecked(insertException);
    }
  }

  /**
   * Appends {@code previousSpec} to compensate for a failed transition. Readback distinguishes a committed write from
   * an unconfirmed compensation while retaining the primary lifecycle or transition exception.
   */
  private void compensateMetadata(
      String id,
      SupervisorSpec previousSpec,
      Throwable primaryException,
      String transitionStage
  )
  {
    final SupervisorSpec latestBeforeInsert = readLatestQuietly(id, primaryException);
    if (latestBeforeInsert instanceof NoopSupervisorSpec) {
      warnTombstoneConflict(id, primaryException, transitionStage);
      return;
    }

    try {
      metadataSupervisorManager.insert(id, previousSpec);
    }
    catch (RuntimeException | LinkageError compensationException) {
      final SupervisorSpec latestSpec = readLatestQuietly(id, compensationException);
      try {
        if (specsExactlyMatch(previousSpec, latestSpec)) {
          log.warn(
              compensationException,
              "Metadata compensation for supervisor [%s] reported failure, but readback confirmed it committed",
              id
          );
          return;
        }
      }
      catch (RuntimeException | LinkageError comparisonException) {
        addSuppressed(compensationException, comparisonException);
      }

      addSuppressed(primaryException, compensationException);
      if (latestSpec instanceof NoopSupervisorSpec) {
        warnTombstoneConflict(id, compensationException, transitionStage);
        return;
      }
      emitTransitionAlert(
          compensationException,
          id,
          transitionStage,
          "Unable to confirm metadata compensation for supervisor [%s] after failure while [%s], runtime state may "
          + "differ from the latest metadata revision, %s",
          id,
          transitionStage,
          repairInstruction(id, previousSpec)
      );
    }
  }

  @Nullable
  private SupervisorSpec readLatestQuietly(String id, Throwable primaryException)
  {
    try {
      return getLatestMetadataSpec(id);
    }
    catch (RuntimeException | LinkageError readException) {
      addSuppressed(primaryException, readException);
      return null;
    }
  }

  private void warnTombstoneConflict(String id, @Nullable Throwable exception, String transitionStage)
  {
    if (exception == null) {
      log.warn(
          "Tombstone observed for supervisor [%s] while [%s]; skipping best-effort metadata write",
          id,
          transitionStage
      );
    } else {
      log.warn(
          exception,
          "Tombstone observed for supervisor [%s] while [%s]; skipping best-effort metadata write",
          id,
          transitionStage
      );
    }
  }

  private static String repairInstruction(String id, SupervisorSpec spec)
  {
    return StringUtils.format(
        "re-issue POST /supervisor/%s/%s to reconcile",
        id,
        spec.isSuspended() ? "suspend" : "resume"
    );
  }

  @Nullable
  private SupervisorSpec getLatestMetadataSpec(String id)
  {
    final List<VersionedSupervisorSpec> versions = metadataSupervisorManager.getAllForId(id, 1);
    return versions.isEmpty() ? null : versions.get(0).getSpec();
  }

  private void emitTransitionAlert(
      @Nullable Throwable primaryException,
      String supervisorId,
      String stage,
      String message,
      Object... arguments
  )
  {
    try {
      log.makeAlert(primaryException, message, arguments)
         .addData("supervisorId", supervisorId)
         .addData("stage", stage)
         .emit();
    }
    catch (Throwable alertException) {
      log.error(alertException, "Failed to emit supervisor metadata inconsistency alert");
    }
  }

  @VisibleForTesting
  boolean specsExactlyMatch(SupervisorSpec expected, @Nullable SupervisorSpec actual)
  {
    if (actual == null
        || !expected.getClass().equals(actual.getClass())
        || !Objects.equals(expected.getType(), actual.getType())
        || !Objects.equals(expected.getId(), actual.getId())) {
      return false;
    }

    try {
      return Objects.equals(jsonMapper.valueToTree(expected), jsonMapper.valueToTree(actual));
    }
    catch (IllegalArgumentException e) {
      throw new RuntimeException("Unable to serialize supervisor specs for exact metadata comparison", e);
    }
  }

  private void restorePreviousRuntime(
      String id,
      SupervisorSpec previousSpec,
      Throwable primaryException
  )
  {
    final SupervisorRuntime restoredRuntime = new SupervisorRuntime();
    try {
      createAndStartSupervisorRuntime(previousSpec, restoredRuntime);
      registerSupervisorRuntime(previousSpec, restoredRuntime);
    }
    catch (Exception | LinkageError restorationException) {
      addSuppressed(primaryException, restorationException);
      cleanupRuntime(restoredRuntime, primaryException, "restored previous", id);
      supervisors.remove(id);
      autoscalers.remove(id);
      emitTransitionAlert(
          restorationException,
          id,
          "restoring the previous runtime",
          "Failed to restore previous runtime for supervisor [%s], re-submit the previous supervisor spec with "
          + "POST /supervisor to recreate the runtime",
          id
      );
    }
  }

  private void cleanupRuntime(
      SupervisorRuntime runtime,
      Throwable primaryException,
      String runtimeDescription,
      String id
  )
  {
    if (runtime.autoscaler != null) {
      try {
        runtime.autoscaler.stop();
      }
      catch (Exception | LinkageError cleanupException) {
        addSuppressed(primaryException, cleanupException);
        log.warn(cleanupException, "Failed to stop %s autoscaler for supervisor [%s]", runtimeDescription, id);
      }
    }
    if (runtime.supervisor != null) {
      try {
        runtime.supervisor.stop(true);
      }
      catch (Exception | LinkageError cleanupException) {
        addSuppressed(primaryException, cleanupException);
        log.warn(cleanupException, "Failed to stop %s supervisor [%s]", runtimeDescription, id);
      }
    }
  }

  private void createAndStartSupervisorRuntime(SupervisorSpec spec, SupervisorRuntime runtime)
  {
    runtime.supervisor = spec.createSupervisor();
    runtime.autoscaler = runtime.supervisor.createAutoscaler(spec);
    runtime.supervisor.start();
    if (runtime.autoscaler != null) {
      runtime.autoscaler.start();
    }
  }

  private void registerSupervisorRuntime(SupervisorSpec spec, SupervisorRuntime runtime)
  {
    final String id = spec.getId();
    supervisors.put(id, Pair.of(runtime.supervisor, spec));
    if (runtime.autoscaler == null) {
      autoscalers.remove(id);
    } else {
      autoscalers.put(id, runtime.autoscaler);
    }
  }

  private static void addSuppressed(Throwable primaryException, Throwable secondaryException)
  {
    if (!Objects.equals(primaryException, secondaryException)) {
      primaryException.addSuppressed(secondaryException);
    }
  }

  private static RuntimeException asUnchecked(Throwable throwable)
  {
    if (throwable instanceof RuntimeException) {
      return (RuntimeException) throwable;
    }
    if (throwable instanceof Error) {
      throw (Error) throwable;
    }
    return new RuntimeException(throwable);
  }

  private static class SupervisorRuntime
  {
    private Supervisor supervisor;
    private SupervisorTaskAutoScaler autoscaler;
  }

  /**
   * Creates a supervisor from the provided spec and starts it if there is not already a supervisor with that id.
   * <p/>
   * Caller should have acquired [lock] before invoking this method to avoid contention with other threads that may be
   * starting, stopping, suspending and resuming supervisors.
   *
   * @return true if a new supervisor was created, false if there was already an existing supervisor with this id
   */
  private boolean createAndStartSupervisorInternal(SupervisorSpec spec, boolean persistSpec)
  {
    String id = spec.getId();
    if (supervisors.containsKey(id)) {
      return false;
    }

    final SupervisorRuntime runtime = new SupervisorRuntime();
    try {
      createAndStartSupervisorRuntime(spec, runtime);
    }
    catch (Exception e) {
      log.error("Failed to create and start supervisor: [%s]", spec.getId());
      throw new RuntimeException(e);
    }

    if (persistSpec) {
      metadataSupervisorManager.insert(id, spec);
    }

    registerSupervisorRuntime(spec, runtime);

    return true;
  }

  private StreamSupervisor requireStreamSupervisor(final String supervisorId, final String operation)
  {
    Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(supervisorId);
    if (supervisor.lhs instanceof StreamSupervisor) {
      return (StreamSupervisor) supervisor.lhs;
    } else {
      throw DruidException.forPersona(DruidException.Persona.USER)
                          .ofCategory(DruidException.Category.UNSUPPORTED)
                          .build(
                              "Operation[%s] is not supported by supervisor[%s] of type[%s].",
                              operation,
                              supervisorId,
                              supervisor.rhs.getType()
                          );
    }
  }

  @Nullable
  private SupervisorSpec getSpec(String id)
  {
    synchronized (lock) {
      Pair<Supervisor, SupervisorSpec> supervisor = supervisors.get(id);
      return supervisor == null ? null : supervisor.rhs;
    }
  }
}
