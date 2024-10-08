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

package org.apache.druid.query.aggregation;

import com.google.common.base.Preconditions;
import org.apache.druid.java.util.common.RE;
import org.apache.druid.java.util.common.io.Closer;
import org.apache.druid.segment.column.ComplexColumn;
import org.apache.druid.segment.serde.cell.ByteBufferProvider;
import org.apache.druid.segment.serde.cell.CellReader;

import javax.annotation.Nullable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SerializablePairLongFloatComplexColumn implements ComplexColumn
{
  private final Closer closer;
  private final int serializedSize;
  private final CellReader cellReader;
  private final AbstractSerializablePairLongObjectDeltaEncodedStagedSerde<?> serde;

  public SerializablePairLongFloatComplexColumn(
      CellReader cellReader,
      AbstractSerializablePairLongObjectDeltaEncodedStagedSerde<?> serde,
      Closer closer,
      int serializedSize
  )
  {
    this.cellReader = cellReader;
    this.serde = serde;
    this.closer = closer;
    this.serializedSize = serializedSize;
  }

  @Override
  public Class<?> getClazz()
  {
    return SerializablePairLongFloat.class;
  }

  @Override
  public String getTypeName()
  {
    return SerializablePairLongFloatComplexMetricSerde.TYPE_NAME;
  }

  @Override
  @Nullable
  public Object getRowValue(int rowNum)
  {
    return serde.deserialize(cellReader.getCell(rowNum));
  }

  @Override
  public int getLength()
  {
    return serializedSize;
  }

  @Override
  public void close()
  {
    try {
      closer.close();
    }
    catch (IOException e) {
      throw new RE(e, "error closing " + getClass().getName());
    }
  }

  public static class Builder
  {
    private final int serializedSize;
    private final AbstractSerializablePairLongObjectDeltaEncodedStagedSerde<?> serde;
    private final CellReader.Builder cellReaderBuilder;

    public Builder(ByteBuffer buffer)
    {
      ByteBuffer masterByteBuffer = buffer.asReadOnlyBuffer().order(ByteOrder.nativeOrder());

      serializedSize = masterByteBuffer.remaining();

      AbstractSerializablePairLongObjectColumnHeader<?> columnHeader =
          AbstractSerializablePairLongObjectColumnHeader.fromBuffer(masterByteBuffer, SerializablePairLongFloat.class);

      Preconditions.checkArgument(
          columnHeader.getVersion() == SerializablePairLongFloatComplexMetricSerde.EXPECTED_VERSION,
          "version %s expected, got %s",
          SerializablePairLongFloatComplexMetricSerde.EXPECTED_VERSION,
          columnHeader.getVersion()
      );

      serde = columnHeader.createSerde();
      cellReaderBuilder = new CellReader.Builder(masterByteBuffer);
    }

    public Builder setByteBufferProvier(ByteBufferProvider byteBufferProvider)
    {
      cellReaderBuilder.setByteBufferProvider(byteBufferProvider);
      return this;
    }

    public SerializablePairLongFloatComplexColumn build()
    {
      Closer closer = Closer.create();
      CellReader cellReader = cellReaderBuilder.build();
      closer.register(cellReader);

      return new SerializablePairLongFloatComplexColumn(cellReader, serde, closer, serializedSize);
    }
  }
}
