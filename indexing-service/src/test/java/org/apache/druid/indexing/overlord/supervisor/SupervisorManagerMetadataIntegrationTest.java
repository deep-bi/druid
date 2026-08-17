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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;
import org.apache.druid.indexing.overlord.DataSourceMetadata;
import org.apache.druid.jackson.DefaultObjectMapper;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.metadata.MetadataStorageTablesConfig;
import org.apache.druid.metadata.SQLMetadataSupervisorManager;
import org.apache.druid.metadata.TestDerbyConnector;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.skife.jdbi.v2.exceptions.CallbackFailedException;

import javax.annotation.Nullable;
import java.sql.SQLTransientException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class SupervisorManagerMetadataIntegrationTest
{
  private static final String SUPERVISOR_ID = "metadata-verification-supervisor";
  private static final List<RecordingSupervisor> CREATED_SUPERVISORS = new CopyOnWriteArrayList<>();

  @Rule
  public final TestDerbyConnector.DerbyConnectorRule derbyConnectorRule =
      new TestDerbyConnector.DerbyConnectorRule();

  private TestDerbyConnector connector;
  private MetadataStorageTablesConfig tablesConfig;
  private FaultInjectingSQLMetadataSupervisorManager metadataSupervisorManager;
  private SupervisorManager supervisorManager;
  private boolean supervisorManagerStarted;

  @Before
  public void setUp()
  {
    CREATED_SUPERVISORS.clear();
    final ObjectMapper mapper = new DefaultObjectMapper();
    mapper.registerSubtypes(IntegrationSupervisorSpec.class);

    connector = derbyConnectorRule.getConnector();
    tablesConfig = derbyConnectorRule.metadataTablesConfigSupplier().get();
    connector.createSupervisorsTable();

    metadataSupervisorManager = new FaultInjectingSQLMetadataSupervisorManager(
        mapper,
        connector,
        Suppliers.ofInstance(tablesConfig)
    );
    metadataSupervisorManager.insert(SUPERVISOR_ID, new IntegrationSupervisorSpec(SUPERVISOR_ID, false));

    supervisorManager = new SupervisorManager(mapper, metadataSupervisorManager);
    supervisorManager.start();
    supervisorManagerStarted = true;
  }

  @After
  public void tearDown()
  {
    if (supervisorManagerStarted) {
      supervisorManager.stop();
    }
    connector.getDBI().withHandle(
        handle -> handle.createStatement(StringUtils.format("DROP TABLE %s", tablesConfig.getSupervisorTable()))
                        .execute()
    );
  }

  @Test
  public void testContinuesSuspendWhenMetadataWriteCommittedBeforeResponseFailure()
  {
    metadataSupervisorManager.failNextInsertAfterCommit();

    Assert.assertTrue(supervisorManager.suspendOrResumeSupervisor(SUPERVISOR_ID, true));

    final SupervisorSpec persistedSpec = metadataSupervisorManager.getLatest().get(SUPERVISOR_ID);
    Assert.assertTrue(persistedSpec.isSuspended());
    Assert.assertTrue(supervisorManager.getSupervisorSpec(SUPERVISOR_ID).get().isSuspended());
    Assert.assertTrue(supervisorManager.getSupervisorIds().contains(SUPERVISOR_ID));

    Assert.assertEquals(2, CREATED_SUPERVISORS.size());
    Assert.assertTrue(CREATED_SUPERVISORS.get(0).stopped);
    Assert.assertTrue(CREATED_SUPERVISORS.get(1).started);
    Assert.assertFalse(CREATED_SUPERVISORS.get(1).stopped);
  }

  @Test
  public void testRetainsRunningSupervisorWhenMetadataWriteDoesNotCommit()
  {
    metadataSupervisorManager.failNextInsertBeforeCommit();

    Assert.assertThrows(
        CallbackFailedException.class,
        () -> supervisorManager.suspendOrResumeSupervisor(SUPERVISOR_ID, true)
    );

    final SupervisorSpec persistedSpec = metadataSupervisorManager.getLatest().get(SUPERVISOR_ID);
    Assert.assertFalse(persistedSpec.isSuspended());
    Assert.assertFalse(supervisorManager.getSupervisorSpec(SUPERVISOR_ID).get().isSuspended());
    Assert.assertTrue(supervisorManager.getSupervisorIds().contains(SUPERVISOR_ID));

    Assert.assertEquals(1, CREATED_SUPERVISORS.size());
    Assert.assertTrue(CREATED_SUPERVISORS.get(0).started);
    Assert.assertFalse(CREATED_SUPERVISORS.get(0).stopped);
  }

  private static class FaultInjectingSQLMetadataSupervisorManager extends SQLMetadataSupervisorManager
  {
    private boolean failNextInsertBeforeCommit;
    private boolean failNextInsertAfterCommit;

    private FaultInjectingSQLMetadataSupervisorManager(
        ObjectMapper jsonMapper,
        TestDerbyConnector connector,
        Supplier<MetadataStorageTablesConfig> dbTables
    )
    {
      super(jsonMapper, connector, dbTables);
    }

    private void failNextInsertAfterCommit()
    {
      failNextInsertAfterCommit = true;
    }

    private void failNextInsertBeforeCommit()
    {
      failNextInsertBeforeCommit = true;
    }

    @Override
    public void insert(String id, SupervisorSpec spec)
    {
      if (failNextInsertBeforeCommit) {
        failNextInsertBeforeCommit = false;
        throw new CallbackFailedException(new SQLTransientException("simulated metadata connection failure"));
      }

      super.insert(id, spec);
      if (failNextInsertAfterCommit) {
        failNextInsertAfterCommit = false;
        throw new RuntimeException("simulated lost metadata write response after commit");
      }
    }
  }

  @JsonTypeName("metadataVerificationIntegration")
  public static class IntegrationSupervisorSpec implements SupervisorSpec
  {
    private final String id;
    private final boolean suspended;

    @JsonCreator
    public IntegrationSupervisorSpec(
        @JsonProperty("id") String id,
        @JsonProperty("suspended") boolean suspended
    )
    {
      this.id = id;
      this.suspended = suspended;
    }

    @Override
    public SupervisorSpec createSuspendedSpec()
    {
      return new IntegrationSupervisorSpec(id, true);
    }

    @Override
    public SupervisorSpec createRunningSpec()
    {
      return new IntegrationSupervisorSpec(id, false);
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
      final RecordingSupervisor supervisor = new RecordingSupervisor();
      CREATED_SUPERVISORS.add(supervisor);
      return supervisor;
    }

    @Override
    @JsonProperty
    public boolean isSuspended()
    {
      return suspended;
    }

    @Override
    public List<String> getDataSources()
    {
      return ImmutableList.of("integration-datasource");
    }

    @Override
    public String getType()
    {
      return "metadataVerificationIntegration";
    }

    @Override
    public String getSource()
    {
      return "integration-source";
    }
  }

  private static class RecordingSupervisor implements Supervisor
  {
    private boolean started;
    private boolean stopped;

    @Override
    public void start()
    {
      started = true;
    }

    @Override
    public void stop(boolean stopGracefully)
    {
      stopped = true;
    }

    @Nullable
    @Override
    public SupervisorReport getStatus()
    {
      return null;
    }

    @Nullable
    @Override
    public SupervisorStateManager.State getState()
    {
      return null;
    }

    @Override
    public void reset(@Nullable DataSourceMetadata dataSourceMetadata)
    {
      // No-op.
    }
  }
}
