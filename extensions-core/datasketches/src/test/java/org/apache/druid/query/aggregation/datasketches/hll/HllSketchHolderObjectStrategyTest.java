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

package org.apache.druid.query.aggregation.datasketches.hll;

import org.apache.datasketches.common.SketchesArgumentException;
import org.apache.datasketches.hll.HllSketch;
import org.apache.datasketches.hll.TgtHllType;
import org.apache.druid.java.util.common.StringEncoding;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.segment.serde.ComplexMetricSerde;
import org.apache.druid.segment.serde.ComplexMetrics;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

public class HllSketchHolderObjectStrategyTest
{
  @Test
  public void testSafeRead()
  {
    HllSketch sketch = new HllSketch();
    sketch.update(new int[]{1, 2, 3});

    final byte[] bytes = sketch.toCompactByteArray();

    ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    HllSketchHolderObjectStrategy objectStrategy = new HllSketchHolderObjectStrategy();

    // valid sketch should not explode when copied, which reads the memory
    objectStrategy.fromByteBufferSafe(buf, bytes.length).getSketch().copy();

    // corrupted sketch should fail with a regular java buffer exception
    for (int subset = 3; subset < bytes.length - 1; subset++) {
      final byte[] garbage2 = new byte[subset];
      for (int i = 0; i < garbage2.length; i++) {
        garbage2[i] = buf.get(i);
      }

      final ByteBuffer buf2 = ByteBuffer.wrap(garbage2).order(ByteOrder.LITTLE_ENDIAN);
      Assert.assertThrows(
          Exception.class, // can throw either SketchesArgumentException or IndexOutOfBoundsException
          () -> objectStrategy.fromByteBufferSafe(buf2, garbage2.length).getSketch().copy()
      );
    }

    // non sketch that is too short to contain header should fail with regular java buffer exception
    final byte[] garbage = new byte[]{0x01, 0x02};
    final ByteBuffer buf3 = ByteBuffer.wrap(garbage).order(ByteOrder.LITTLE_ENDIAN);
    Assert.assertThrows(
        SketchesArgumentException.class,
        () -> objectStrategy.fromByteBufferSafe(buf3, garbage.length).getSketch().copy()
    );

    // non sketch that is long enough to check (this one doesn't actually need 'safe' read)
    final byte[] garbageLonger = StringUtils.toUtf8("notasketch");
    final ByteBuffer buf4 = ByteBuffer.wrap(garbageLonger).order(ByteOrder.LITTLE_ENDIAN);
    Assert.assertThrows(
        SketchesArgumentException.class,
        () -> objectStrategy.fromByteBufferSafe(buf4, garbageLonger.length).getSketch().copy()
    );
  }

  @Test
  public void testHllSketchIsNullEquivalent()
  {
    final Random random = new Random(0);
    for (final TgtHllType tgtHllType : TgtHllType.values()) {
      for (int lgK = 7; lgK < 22; lgK++) {
        for (int sz : new int[]{0, 1, 2, 127, 128, 129, 255, 256, 257, 511, 512, 513, 16383, 16384, 16385}) {
          final String description = StringUtils.format("tgtHllType[%s], lgK[%s], sz[%s]", tgtHllType, lgK, sz);
          final HllSketch sketch = new HllSketch(lgK, tgtHllType);
          for (int i = 0; i < sz; i++) {
            sketch.update(random.nextLong());
          }

          final boolean expectEmpty = sz == 0;

          // --------------------------------
          // Compact array, little endian buf
          final byte[] compactBytes = sketch.toCompactByteArray();
          // Add a byte of padding on either side
          ByteBuffer buf = ByteBuffer.allocate(compactBytes.length + 2);
          buf.order(ByteOrder.LITTLE_ENDIAN);
          buf.position(1);
          buf.put(compactBytes);
          buf.position(1);
          Assert.assertEquals(
              "Compact array littleEndian " + description,
              expectEmpty,
              HllSketchHolderObjectStrategy.isSafeToConvertToNullSketch(buf, compactBytes.length)
          );
          Assert.assertEquals(1, buf.position());

          // -----------------------------
          // Compact array, big endian buf
          buf.order(ByteOrder.BIG_ENDIAN);
          Assert.assertEquals(
              "Compact array bigEndian " + description,
              expectEmpty,
              HllSketchHolderObjectStrategy.isSafeToConvertToNullSketch(buf, compactBytes.length)
          );
          Assert.assertEquals(1, buf.position());

          // ----------------------------------
          // Updatable array, little endian buf
          final byte[] updatableBytes = sketch.toUpdatableByteArray();
          // Add a byte of padding on either side
          buf = ByteBuffer.allocate(updatableBytes.length + 2);
          buf.order(ByteOrder.LITTLE_ENDIAN);
          buf.position(1);
          buf.put(updatableBytes);
          buf.position(1);
          Assert.assertEquals(
              "Updatable array littleEndian " + description,
              expectEmpty,
              HllSketchHolderObjectStrategy.isSafeToConvertToNullSketch(buf, updatableBytes.length)
          );
          Assert.assertEquals(1, buf.position());

          // -------------------------------
          // Updatable array, big endian buf
          buf.order(ByteOrder.BIG_ENDIAN);
          Assert.assertEquals(
              "Updatable array bigEndian " + description,
              expectEmpty,
              HllSketchHolderObjectStrategy.isSafeToConvertToNullSketch(buf, updatableBytes.length)
          );
          Assert.assertEquals(1, buf.position());
        }
      }
    }
  }


  @Test
  public void testComplexSerdeToBytesOnRealtimeSegmentSketch()
  {
    ComplexMetrics.registerSerde(HllSketchModule.BUILD_TYPE_NAME, new HllSketchBuildComplexMetricSerde());
    ComplexMetricSerde serde = ComplexMetrics.getSerdeForType(HllSketchModule.BUILD_TYPE_NAME);
    Assert.assertNotNull(serde);
    HllSketch sketchNew = new HllSketch(14, TgtHllType.HLL_8);
    HllSketchBuildUtil.updateSketch(sketchNew, StringEncoding.UTF16LE, new int[]{1, 2});

    HllSketchHolder sketchHolder = HllSketchHolder.of(sketchNew);

    byte[] bytes = serde.toBytes(sketchHolder);
    Assert.assertEquals(bytes, serde.toBytes(bytes));

    HllSketchHolder fromBytesHolder = (HllSketchHolder) serde.fromBytes(bytes, 0, bytes.length);

    Assert.assertEquals(sketchHolder.getSketch().getLgConfigK(), fromBytesHolder.getSketch().getLgConfigK());
    Assert.assertEquals(sketchHolder.getSketch().getTgtHllType(), fromBytesHolder.getSketch().getTgtHllType());
    Assert.assertEquals(
        sketchHolder.getSketch().getCompactSerializationBytes(),
        fromBytesHolder.getSketch().getCompactSerializationBytes()
    );
    Assert.assertEquals(
        sketchHolder.getSketch().getUpdatableSerializationBytes(),
        fromBytesHolder.getSketch().getUpdatableSerializationBytes()
    );
    Assert.assertEquals(sketchHolder.getSketch().getEstimate(), fromBytesHolder.getSketch().getEstimate(), 0);
    Assert.assertEquals(sketchHolder.getSketch().getLowerBound(1), fromBytesHolder.getSketch().getLowerBound(1), 0);
    Assert.assertEquals(sketchHolder.getSketch().getUpperBound(1), fromBytesHolder.getSketch().getUpperBound(1), 0);

    // During fromBytes() sketches field memory changes to TRUE
    Assert.assertFalse(sketchHolder.getSketch().isMemory());
    Assert.assertTrue(fromBytesHolder.getSketch().isMemory());
  }
}
