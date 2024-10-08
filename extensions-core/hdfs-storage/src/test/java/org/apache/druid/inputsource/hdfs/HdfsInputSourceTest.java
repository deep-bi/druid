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

package org.apache.druid.inputsource.hdfs;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.InjectableValues.Std;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.apache.druid.data.input.ColumnsFilter;
import org.apache.druid.data.input.InputFormat;
import org.apache.druid.data.input.InputRow;
import org.apache.druid.data.input.InputRowSchema;
import org.apache.druid.data.input.InputSource;
import org.apache.druid.data.input.InputSourceReader;
import org.apache.druid.data.input.InputSplit;
import org.apache.druid.data.input.InputStats;
import org.apache.druid.data.input.MaxSizeSplitHintSpec;
import org.apache.druid.data.input.impl.CsvInputFormat;
import org.apache.druid.data.input.impl.DimensionsSpec;
import org.apache.druid.data.input.impl.InputStatsImpl;
import org.apache.druid.data.input.impl.TimestampSpec;
import org.apache.druid.data.input.impl.systemfield.SystemField;
import org.apache.druid.data.input.impl.systemfield.SystemFields;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.common.parsers.CloseableIterator;
import org.apache.druid.storage.hdfs.HdfsStorageDruidModule;
import org.apache.druid.testing.InitializedNullHandlingTest;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.LocalFileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class HdfsInputSourceTest extends InitializedNullHandlingTest
{
  private static final String PATH = "hdfs://localhost:7020/foo/bar";
  private static final Configuration CONFIGURATION = new Configuration();
  private static final HdfsInputSourceConfig DEFAULT_INPUT_SOURCE_CONFIG = new HdfsInputSourceConfig(null);
  private static final String COLUMN = "value";
  private static final InputRowSchema INPUT_ROW_SCHEMA = new InputRowSchema(
      new TimestampSpec(null, null, null),
      DimensionsSpec.EMPTY,
      ColumnsFilter.all()
  );
  private static final InputFormat INPUT_FORMAT = new CsvInputFormat(
      Arrays.asList(TimestampSpec.DEFAULT_COLUMN, COLUMN),
      null,
      false,
      null,
      0,
      null
  );

  public static class ConstructorTest
  {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testConstructorAllowsOnlyDefaultProtocol()
    {
      HdfsInputSource.builder()
                     .paths(PATH + "*")
                     .configuration(CONFIGURATION)
                     .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                     .build();

      expectedException.expect(IllegalArgumentException.class);
      expectedException.expectMessage("Only [hdfs] protocols are allowed");
      HdfsInputSource.builder()
                     .paths("file:/foo/bar*")
                     .configuration(CONFIGURATION)
                     .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                     .build();
    }

    @Test
    public void testConstructorAllowsOnlyCustomProtocol()
    {
      final Configuration conf = new Configuration();
      conf.set("fs.ftp.impl", "org.apache.hadoop.fs.ftp.FTPFileSystem");
      HdfsInputSource.builder()
                     .paths("ftp://localhost:21/foo/bar")
                     .configuration(CONFIGURATION)
                     .inputSourceConfig(new HdfsInputSourceConfig(ImmutableSet.of("ftp")))
                     .build();

      expectedException.expect(IllegalArgumentException.class);
      expectedException.expectMessage("Only [druid] protocols are allowed");
      HdfsInputSource.builder()
                     .paths(PATH + "*")
                     .configuration(CONFIGURATION)
                     .inputSourceConfig(new HdfsInputSourceConfig(ImmutableSet.of("druid")))
                     .build();
    }

    @Test
    public void testConstructorWithDefaultHdfs()
    {
      final Configuration conf = new Configuration();
      conf.set("fs.default.name", "hdfs://localhost:7020");
      HdfsInputSource.builder()
                     .paths("/foo/bar*")
                     .configuration(conf)
                     .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                     .build();

      HdfsInputSource.builder()
                     .paths("foo/bar*")
                     .configuration(conf)
                     .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                     .build();

      HdfsInputSource.builder()
                     .paths("hdfs:///foo/bar*")
                     .configuration(conf)
                     .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                     .build();

      HdfsInputSource.builder()
                     .paths("hdfs://localhost:10020/foo/bar*") // different hdfs
                     .configuration(conf)
                     .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                     .build();
    }

    @Test
    public void testGetTypes()
    {
      final Configuration conf = new Configuration();
      conf.set("fs.default.name", "hdfs://localhost:7020");
      HdfsInputSource inputSource =
          HdfsInputSource.builder()
                         .paths("/foo/bar*")
                         .configuration(conf)
                         .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                         .build();

      Assert.assertEquals(Collections.singleton(HdfsInputSource.TYPE_KEY), inputSource.getTypes());
    }
  }

  public static class SerializeDeserializeTest
  {
    private static final ObjectMapper OBJECT_MAPPER = createObjectMapper();

    private HdfsInputSource.Builder hdfsInputSourceBuilder;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setup()
    {
      hdfsInputSourceBuilder = HdfsInputSource.builder()
                                              .paths(PATH)
                                              .configuration(CONFIGURATION)
                                              .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG);
    }

    @Test
    public void requiresPathsAsStringOrArrayOfStrings()
    {
      exception.expect(IllegalArgumentException.class);
      exception.expectMessage("'paths' must be a string or an array of strings");

      hdfsInputSourceBuilder.paths(Arrays.asList("a", 1)).build();
    }

    @Test
    public void serializesDeserializesWithArrayPaths()
    {
      Wrapper target = new Wrapper(hdfsInputSourceBuilder.paths(Collections.singletonList(PATH)));
      testSerializesDeserializes(target);
    }

    @Test
    public void serializesDeserializesStringPaths()
    {
      Wrapper target = new Wrapper(hdfsInputSourceBuilder.paths(PATH));
      testSerializesDeserializes(target);
    }

    @Test
    public void serializesDeserializesStringPathsWithSystemFields()
    {
      Wrapper target = new Wrapper(hdfsInputSourceBuilder.paths(PATH).systemFields(SystemField.URI));
      testSerializesDeserializes(target);
    }

    private static void testSerializesDeserializes(Wrapper hdfsInputSourceWrapper)
    {
      try {
        String serialized = OBJECT_MAPPER.writeValueAsString(hdfsInputSourceWrapper);
        Wrapper deserialized = OBJECT_MAPPER.readValue(serialized, Wrapper.class);
        Assert.assertEquals(serialized, OBJECT_MAPPER.writeValueAsString(deserialized));
      }
      catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }

    private static ObjectMapper createObjectMapper()
    {
      final ObjectMapper mapper = new ObjectMapper();
      mapper.setInjectableValues(
          new Std()
              .addValue(Configuration.class, new Configuration())
              .addValue(HdfsInputSourceConfig.class, DEFAULT_INPUT_SOURCE_CONFIG)
      );
      new HdfsStorageDruidModule().getJacksonModules().forEach(mapper::registerModule);
      return mapper;
    }

    // Helper to test HdfsInputSource is added correctly to HdfsStorageDruidModule
    private static class Wrapper
    {
      @JsonProperty
      InputSource inputSource;

      @SuppressWarnings("unused")  // used by Jackson
      private Wrapper()
      {
      }

      Wrapper(HdfsInputSource.Builder hdfsInputSourceBuilder)
      {
        this.inputSource = hdfsInputSourceBuilder.build();
      }
    }
  }

  public static class ReaderTest
  {
    private static final String PATH = "test";
    private static final int NUM_FILE = 3;
    private static final String KEY_VALUE_SEPARATOR = ",";
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private FileSystem fileSystem;
    private HdfsInputSource target;
    private Set<Path> paths;
    private Map<Long, String> timestampToValue;
    private List<String> fileContents;

    @Before
    public void setup() throws IOException
    {
      timestampToValue = new HashMap<>();
      fileContents = new ArrayList<>();

      File dir = temporaryFolder.getRoot();
      Configuration configuration = new Configuration(true);
      fileSystem = new LocalFileSystem();
      fileSystem.initialize(dir.toURI(), configuration);
      fileSystem.setWorkingDirectory(new Path(dir.getAbsolutePath()));

      paths = IntStream.range(0, NUM_FILE)
                       .mapToObj(
                           i -> {
                             char value = ALPHABET.charAt(i % ALPHABET.length());
                             timestampToValue.put((long) i, Character.toString(value));

                             final String contents = i + KEY_VALUE_SEPARATOR + value;
                             fileContents.add(contents);
                             return createFile(fileSystem, String.valueOf(i), contents);
                           }
                       )
                       .collect(Collectors.toSet());

      target = HdfsInputSource.builder()
                              .paths(fileSystem.makeQualified(new Path(PATH)) + "*")
                              .configuration(CONFIGURATION)
                              .inputSourceConfig(new HdfsInputSourceConfig(ImmutableSet.of("hdfs", "file")))
                              .build();
    }

    @After
    public void teardown() throws IOException
    {
      temporaryFolder.delete();
      fileSystem.close();
    }

    private static Path createFile(FileSystem fs, String pathSuffix, String contents)
    {
      try {
        Path path = new Path(PATH + pathSuffix);
        try (Writer writer = new BufferedWriter(
            new OutputStreamWriter(fs.create(path), StandardCharsets.UTF_8)
        )) {
          writer.write(contents);
        }
        return fs.makeQualified(path);
      }
      catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }

    @Test
    public void readsSplitsCorrectly() throws IOException
    {
      InputSourceReader reader = target.formattableReader(INPUT_ROW_SCHEMA, INPUT_FORMAT, null);
      final InputStats inputStats = new InputStatsImpl();

      Map<Long, String> actualTimestampToValue = new HashMap<>();
      try (CloseableIterator<InputRow> iterator = reader.read(inputStats)) {
        while (iterator.hasNext()) {
          InputRow row = iterator.next();
          actualTimestampToValue.put(row.getTimestampFromEpoch(), row.getDimension(COLUMN).get(0));
        }
      }

      Assert.assertEquals(timestampToValue, actualTimestampToValue);

      long totalFileSize = fileContents.stream().mapToLong(String::length).sum();
      Assert.assertEquals(totalFileSize, inputStats.getProcessedBytes());
    }

    @Test
    public void hasCorrectSplits() throws IOException
    {
      // Set maxSplitSize to 1 so that each inputSplit has only one object
      List<InputSplit<List<Path>>> splits = target.createSplits(null, new MaxSizeSplitHintSpec(1L, null))
                                                  .collect(Collectors.toList());
      splits.forEach(split -> Assert.assertEquals(1, split.get().size()));
      Set<Path> actualPaths = splits.stream()
                                    .flatMap(split -> split.get().stream())
                                    .collect(Collectors.toSet());
      Assert.assertEquals(paths, actualPaths);
    }

    @Test
    public void createSplitsRespectSplitHintSpec() throws IOException
    {
      List<InputSplit<List<Path>>> splits = target.createSplits(null, new MaxSizeSplitHintSpec(7L, null))
                                                  .collect(Collectors.toList());
      Assert.assertEquals(2, splits.size());
      Assert.assertEquals(2, splits.get(0).get().size());
      Assert.assertEquals(1, splits.get(1).get().size());
    }

    @Test
    public void hasCorrectNumberOfSplits() throws IOException
    {
      // Set maxSplitSize to 1 so that each inputSplit has only one object
      int numSplits = target.estimateNumSplits(null, new MaxSizeSplitHintSpec(1L, null));
      Assert.assertEquals(NUM_FILE, numSplits);
    }

    @Test
    public void createCorrectInputSourceWithSplit() throws Exception
    {
      List<InputSplit<List<Path>>> splits = target.createSplits(null, new MaxSizeSplitHintSpec(null, 1))
                                                  .collect(Collectors.toList());

      for (InputSplit<List<Path>> split : splits) {
        String expectedPath = Iterables.getOnlyElement(split.get()).toString();
        HdfsInputSource inputSource = (HdfsInputSource) target.withSplit(split);
        String actualPath = Iterables.getOnlyElement(inputSource.getInputPaths());
        Assert.assertEquals(expectedPath, actualPath);
      }
    }
  }

  public static class EmptyPathsTest
  {
    private HdfsInputSource target;

    @Before
    public void setup()
    {
      target = HdfsInputSource.builder()
                              .paths(Collections.emptyList())
                              .configuration(CONFIGURATION)
                              .inputSourceConfig(DEFAULT_INPUT_SOURCE_CONFIG)
                              .build();
    }

    @Test
    public void readsSplitsCorrectly() throws IOException
    {
      InputSourceReader reader = target.formattableReader(INPUT_ROW_SCHEMA, INPUT_FORMAT, null);
      final InputStats inputStats = new InputStatsImpl();

      try (CloseableIterator<InputRow> iterator = reader.read(inputStats)) {
        Assert.assertFalse(iterator.hasNext());
      }
      Assert.assertEquals(0, inputStats.getProcessedBytes());
    }

    @Test
    public void hasCorrectSplits() throws IOException
    {
      List<InputSplit<List<Path>>> splits = target.createSplits(null, null)
                                                  .collect(Collectors.toList());
      Assert.assertTrue(String.valueOf(splits), splits.isEmpty());
    }

    @Test
    public void hasCorrectNumberOfSplits() throws IOException
    {
      int numSplits = target.estimateNumSplits(null, null);
      Assert.assertEquals(0, numSplits);
    }
  }

  public static class SystemFieldsTest
  {
    @Test
    public void testSystemFields()
    {
      final Configuration configuration = new Configuration();
      final HdfsInputSource inputSource = new HdfsInputSource(
          "hdfs://127.0.0.1/bar",
          new SystemFields(EnumSet.of(SystemField.URI, SystemField.PATH)),
          configuration,
          new HdfsInputSourceConfig(null)
      );

      Assert.assertEquals(
          EnumSet.of(SystemField.URI, SystemField.PATH),
          inputSource.getConfiguredSystemFields()
      );

      final HdfsInputEntity entity = new HdfsInputEntity(configuration, new Path("hdfs://127.0.0.1/bar"));
      Assert.assertEquals("hdfs://127.0.0.1/bar", inputSource.getSystemFieldValue(entity, SystemField.URI));
      Assert.assertEquals("/bar", inputSource.getSystemFieldValue(entity, SystemField.PATH));

      final HdfsInputEntity entity2 = new HdfsInputEntity(configuration, new Path("/127.0.0.1/bar"));
      Assert.assertEquals("file:///127.0.0.1/bar", inputSource.getSystemFieldValue(entity2, SystemField.URI));
      Assert.assertEquals("/127.0.0.1/bar", inputSource.getSystemFieldValue(entity2, SystemField.PATH));

      final HdfsInputEntity entity3 = new HdfsInputEntity(configuration, new Path("bar"));
      Assert.assertEquals(
          StringUtils.format("file:%s/bar", System.getProperty("user.dir")),
          inputSource.getSystemFieldValue(entity3, SystemField.URI)
      );
      Assert.assertEquals(
          StringUtils.format("%s/bar", System.getProperty("user.dir")),
          inputSource.getSystemFieldValue(entity3, SystemField.PATH)
      );
    }
  }

  public static class EqualsTest
  {
    @Test
    public void testEquals()
    {
      EqualsVerifier.forClass(HdfsInputSource.class)
                    .usingGetClass()
                    .withIgnoredFields("cachedPaths")
                    .withPrefabValues(Configuration.class, new Configuration(), new Configuration())
                    .verify();
    }
  }
}
