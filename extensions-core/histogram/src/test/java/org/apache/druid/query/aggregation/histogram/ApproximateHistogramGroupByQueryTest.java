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

package org.apache.druid.query.aggregation.histogram;

import com.google.common.collect.ImmutableList;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.common.io.Closer;
import org.apache.druid.query.QueryPlus;
import org.apache.druid.query.QueryRunner;
import org.apache.druid.query.QueryRunnerTestHelper;
import org.apache.druid.query.dimension.DefaultDimensionSpec;
import org.apache.druid.query.groupby.GroupByQuery;
import org.apache.druid.query.groupby.GroupByQueryConfig;
import org.apache.druid.query.groupby.GroupByQueryRunnerFactory;
import org.apache.druid.query.groupby.GroupByQueryRunnerTest;
import org.apache.druid.query.groupby.GroupByQueryRunnerTestHelper;
import org.apache.druid.query.groupby.ResultRow;
import org.apache.druid.query.groupby.TestGroupByBuffers;
import org.apache.druid.query.groupby.orderby.DefaultLimitSpec;
import org.apache.druid.query.groupby.orderby.OrderByColumnSpec;
import org.apache.druid.segment.TestHelper;
import org.apache.druid.testing.InitializedNullHandlingTest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 */
@RunWith(Parameterized.class)
public class ApproximateHistogramGroupByQueryTest extends InitializedNullHandlingTest
{
  private static final Closer RESOURCE_CLOSER = Closer.create();
  private static TestGroupByBuffers BUFFER_POOLS = null;

  private final QueryRunner<ResultRow> runner;
  private final GroupByQueryRunnerFactory factory;

  @BeforeClass
  public static void setUpClass()
  {
    if (BUFFER_POOLS == null) {
      BUFFER_POOLS = TestGroupByBuffers.createDefault();
    }
  }

  @AfterClass
  public static void tearDownClass()
  {
    BUFFER_POOLS.close();
    BUFFER_POOLS = null;
  }

  @Parameterized.Parameters(name = "{0}")
  public static Iterable<Object[]> constructorFeeder()
  {
    setUpClass();

    final GroupByQueryConfig v2Config = new GroupByQueryConfig()
    {

      @Override
      public String toString()
      {
        return "v2";
      }
    };

    final List<Object[]> constructors = new ArrayList<>();
    final List<GroupByQueryConfig> configs = ImmutableList.of(
        v2Config
    );

    for (GroupByQueryConfig config : configs) {
      final GroupByQueryRunnerFactory factory = GroupByQueryRunnerTest.makeQueryRunnerFactory(config, BUFFER_POOLS);
      for (QueryRunner<ResultRow> runner : QueryRunnerTestHelper.makeQueryRunnersToMerge(factory, false)) {
        final String testName = StringUtils.format(
            "config=%s, runner=%s",
            config.toString(),
            runner.toString()
        );
        constructors.add(new Object[]{testName, factory, runner});
      }
    }

    return constructors;
  }

  public ApproximateHistogramGroupByQueryTest(
      String testName,
      GroupByQueryRunnerFactory factory,
      QueryRunner runner
  )
  {
    this.factory = factory;
    this.runner = runner;
    ApproximateHistogramDruidModule.registerSerde();
  }

  @After
  public void teardown() throws IOException
  {
    RESOURCE_CLOSER.close();
  }

  @Test
  public void testGroupByWithApproximateHistogramAgg()
  {
    ApproximateHistogramAggregatorFactory aggFactory = new ApproximateHistogramAggregatorFactory(
        "apphisto",
        "index",
        10,
        5,
        Float.NEGATIVE_INFINITY,
        Float.POSITIVE_INFINITY,
        false
    );

    GroupByQuery query = new GroupByQuery.Builder()
        .setDataSource(QueryRunnerTestHelper.DATA_SOURCE)
        .setGranularity(QueryRunnerTestHelper.ALL_GRAN).setDimensions(new DefaultDimensionSpec(
            QueryRunnerTestHelper.MARKET_DIMENSION,
            "marketalias"
        ))
        .setInterval(QueryRunnerTestHelper.FULL_ON_INTERVAL_SPEC)
        .setLimitSpec(
            new DefaultLimitSpec(
                Collections.singletonList(new OrderByColumnSpec("marketalias", OrderByColumnSpec.Direction.DESCENDING)),
                1
            )
        ).setAggregatorSpecs(QueryRunnerTestHelper.ROWS_COUNT, aggFactory)
        .setPostAggregatorSpecs(
            Collections.singletonList(
                new QuantilePostAggregator("quantile", "apphisto", 0.5f)
            )
        )
        .build();

    List<ResultRow> expectedResults = Collections.singletonList(
        GroupByQueryRunnerTestHelper.createExpectedRow(
            query,
            "1970-01-01T00:00:00.000Z",
            "marketalias", "upfront",
            "rows", 186L,
            "quantile", 880.9881f,
            "apphisto",
            new Histogram(
                new float[]{
                    214.97299194335938f,
                    545.9906005859375f,
                    877.0081787109375f,
                    1208.0257568359375f,
                    1539.0433349609375f,
                    1870.06103515625f
                },
                new double[]{
                    0.0, 67.53287506103516, 72.22068786621094, 31.984678268432617, 14.261756896972656
                }
            )
        )
    );

    Iterable<ResultRow> results = runner.run(QueryPlus.wrap(GroupByQueryRunnerTestHelper.populateResourceId(query)))
                                        .toList();
    TestHelper.assertExpectedObjects(expectedResults, results, "approx-histo");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGroupByWithSameNameComplexPostAgg()
  {
    ApproximateHistogramAggregatorFactory aggFactory = new ApproximateHistogramAggregatorFactory(
        "quantile",
        "index",
        10,
        5,
        Float.NEGATIVE_INFINITY,
        Float.POSITIVE_INFINITY,
        false
    );

    GroupByQuery query = new GroupByQuery.Builder()
        .setDataSource(QueryRunnerTestHelper.DATA_SOURCE)
        .setGranularity(QueryRunnerTestHelper.ALL_GRAN).setDimensions(new DefaultDimensionSpec(
            QueryRunnerTestHelper.MARKET_DIMENSION,
            "marketalias"
        ))
        .setInterval(QueryRunnerTestHelper.FULL_ON_INTERVAL_SPEC)
        .setLimitSpec(
            new DefaultLimitSpec(
                Collections.singletonList(new OrderByColumnSpec("marketalias", OrderByColumnSpec.Direction.DESCENDING)),
                1
            )
        ).setAggregatorSpecs(QueryRunnerTestHelper.ROWS_COUNT, aggFactory)
        .setPostAggregatorSpecs(
            Collections.singletonList(
                new QuantilePostAggregator("quantile", "quantile", 0.5f)
            )
        )
        .build();

    List<ResultRow> expectedResults = Collections.singletonList(
        GroupByQueryRunnerTestHelper.createExpectedRow(
            query,
            "1970-01-01T00:00:00.000Z",
            "marketalias", "upfront",
            "rows", 186L,
            "quantile", 880.9881f
        )
    );

    Iterable<ResultRow> results = runner.run(QueryPlus.wrap(GroupByQueryRunnerTestHelper.populateResourceId(query)))
                                        .toList();
    TestHelper.assertExpectedObjects(expectedResults, results, "approx-histo");
  }
}
