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

package org.apache.druid.data.input.avro;

import org.apache.avro.Schema;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.mapreduce.AvroJob;
import org.apache.commons.lang3.StringUtils;
import org.apache.druid.java.util.common.logger.Logger;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;

import java.io.IOException;

@SuppressWarnings("unused") // This class should be specified and used via hadoop ioConfig, see avro.md
public class AvroValueInputFormat extends FileInputFormat<NullWritable, GenericRecord>
{
  private static final Logger log = new Logger(AvroValueInputFormat.class);

  private static final String CONF_INPUT_VALUE_SCHEMA_PATH = "avro.schema.input.value.path";

  /**
   * {@inheritDoc}
   */
  @Override
  public RecordReader<NullWritable, GenericRecord> createRecordReader(InputSplit split, TaskAttemptContext context)
      throws IOException
  {
    Schema readerSchema = AvroJob.getInputValueSchema(context.getConfiguration());

    if (readerSchema == null) {
      String schemaFilePath = context.getConfiguration().get(CONF_INPUT_VALUE_SCHEMA_PATH);
      if (StringUtils.isNotBlank(schemaFilePath)) {
        log.info("Using file: %s as reader schema.", schemaFilePath);
        try (FSDataInputStream inputStream =
            FileSystem.get(context.getConfiguration()).open(new Path(schemaFilePath))) {
          readerSchema = new Schema.Parser().parse(inputStream);
        }
      }
    }

    if (null == readerSchema) {
      log.warn("Reader schema was not set. Use AvroJob.setInputKeySchema() if desired.");
      log.info("Using a reader schema equal to the writer schema.");
    }
    return new AvroValueRecordReader(readerSchema);
  }
}
