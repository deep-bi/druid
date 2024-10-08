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

package org.apache.druid.segment.join;

import com.google.common.annotations.VisibleForTesting;
import org.apache.druid.query.filter.Filter;
import org.apache.druid.query.filter.ValueMatcher;
import org.apache.druid.segment.ColumnSelectorFactory;
import org.apache.druid.segment.Cursor;
import org.apache.druid.segment.CursorBuildSpec;
import org.apache.druid.segment.VirtualColumns;

import javax.annotation.Nullable;

/**
 * A Cursor decorator used by {@link HashJoinSegmentCursorFactory#makeCursorHolder(CursorBuildSpec)} to add post-join
 * virtual columns and filters.
 */
public class PostJoinCursor implements Cursor
{
  private final Cursor baseCursor;
  private final ColumnSelectorFactory columnSelectorFactory;

  @Nullable
  private ValueMatcher valueMatcher;

  @Nullable
  private final Filter postJoinFilter;

  private PostJoinCursor(Cursor baseCursor, VirtualColumns virtualColumns, @Nullable Filter filter)
  {
    this.baseCursor = baseCursor;

    this.columnSelectorFactory = virtualColumns.wrap(baseCursor.getColumnSelectorFactory());

    if (filter == null) {
      this.valueMatcher = null;
    } else {
      this.valueMatcher = filter.makeMatcher(this.columnSelectorFactory);
    }
    this.postJoinFilter = filter;
  }

  public static PostJoinCursor wrap(
      final Cursor baseCursor,
      final VirtualColumns virtualColumns,
      @Nullable final Filter filter
  )
  {
    final PostJoinCursor postJoinCursor = new PostJoinCursor(baseCursor, virtualColumns, filter);
    postJoinCursor.advanceToMatch();
    return postJoinCursor;
  }

  @VisibleForTesting
  public void setValueMatcher(@Nullable ValueMatcher valueMatcher)
  {
    this.valueMatcher = valueMatcher;
  }

  private void advanceToMatch()
  {
    if (valueMatcher != null) {
      while (!isDone() && !valueMatcher.matches(false)) {
        baseCursor.advance();
      }
    }
  }

  @Override
  public ColumnSelectorFactory getColumnSelectorFactory()
  {
    return columnSelectorFactory;
  }

  @Nullable
  public Filter getPostJoinFilter()
  {
    return postJoinFilter;
  }

  @Override
  public void advance()
  {
    baseCursor.advance();
    // Relies on baseCursor.advance() call inside this for BaseQuery.checkInterrupted() checks -- unlike other cursors
    // which call advanceInterruptibly() and hence have to explicitly provision for interrupts.
    advanceToMatch();
  }


  /**
   * Advancing the post-join requires evaluating the join on whole segment and advancing without interruption can take
   * a long time if there are no matches but the join itself is big. This can leave the thread running well after
   * the timeout elapses. One such issue is described in
   * <a href="https://github.com/apache/druid/issues/14514">CPU thread running PostJoinCursor cannot be terminated</a>
   */
  @Override
  public void advanceUninterruptibly()
  {
    advance();
  }

  @Override
  public boolean isDone()
  {
    return baseCursor.isDone();
  }

  @Override
  public boolean isDoneOrInterrupted()
  {
    return baseCursor.isDoneOrInterrupted();
  }

  @Override
  public void reset()
  {
    baseCursor.reset();
    advanceToMatch();
  }
}
