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

package org.apache.druid.sql.calcite.expression;

import org.apache.druid.math.expr.Parser;
import org.apache.druid.query.expression.TestExprMacroTable;
import org.apache.druid.segment.column.ColumnType;
import org.apache.druid.segment.virtual.ExpressionVirtualColumn;
import org.apache.druid.sql.calcite.planner.ExpressionParser;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;

public class DruidExpressionVCBitmapIndexTest
{

  private static final ExpressionParser PARSER = expression -> Parser.parse(expression, TestExprMacroTable.INSTANCE);

  @Test
  public void testToVirtualColumnBitmapIndex()
  {
    DruidExpression exprWithBitmap =
        DruidExpression.ofExpression(
            ColumnType.STRING,
            args -> "\"x\"",
            Collections.emptyList(),
            true
        );

    DruidExpression exprWithoutBitmap =
        DruidExpression.ofExpression(
            ColumnType.STRING,
            args -> "\"x\"",
            Collections.emptyList(),
            false
        );

    ExpressionVirtualColumn indexed =
        (ExpressionVirtualColumn) exprWithBitmap.toVirtualColumn("vWith", ColumnType.STRING, PARSER);
    ExpressionVirtualColumn notIndexed =
        (ExpressionVirtualColumn) exprWithoutBitmap.toVirtualColumn("vWithout", ColumnType.STRING, PARSER);

    Assert.assertTrue(indexed.isEnableBitmapIndexes());
    Assert.assertFalse(notIndexed.isEnableBitmapIndexes());
  }

  @Test
  public void testToExpressionVirtualColumnBitmapIndex()
  {
    DruidExpression baseExpr =
        DruidExpression.ofExpression(
            ColumnType.STRING,
            args -> "\"x\"",
            Collections.emptyList(),
            false
        );

    ExpressionVirtualColumn indexed =
        (ExpressionVirtualColumn) baseExpr.toExpressionVirtualColumn("vForcedTrue", ColumnType.STRING, PARSER, true);
    ExpressionVirtualColumn notIndexed =
        (ExpressionVirtualColumn) baseExpr.toExpressionVirtualColumn("vForcedFalse", ColumnType.STRING, PARSER, false);

    Assert.assertTrue(indexed.isEnableBitmapIndexes());
    Assert.assertFalse(notIndexed.isEnableBitmapIndexes());
  }
}