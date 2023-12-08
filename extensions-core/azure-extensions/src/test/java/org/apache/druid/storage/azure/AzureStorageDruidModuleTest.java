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

package org.apache.druid.storage.azure;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.inject.Binder;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.ProvisionException;
import com.google.inject.TypeLiteral;
import com.microsoft.azure.storage.StorageCredentials;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.ListBlobItem;
import org.apache.druid.data.input.azure.AzureEntityFactory;
import org.apache.druid.data.input.impl.CloudObjectLocation;
import org.apache.druid.guice.DruidGuiceExtensions;
import org.apache.druid.guice.JsonConfigurator;
import org.apache.druid.guice.LazySingleton;
import org.apache.druid.jackson.JacksonModule;
import org.apache.druid.segment.loading.OmniDataSegmentKiller;
import org.apache.druid.storage.azure.blob.ListBlobItemHolder;
import org.apache.druid.storage.azure.blob.ListBlobItemHolderFactory;
import org.easymock.EasyMock;
import org.easymock.EasyMockSupport;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.validation.Validation;
import javax.validation.Validator;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

public class AzureStorageDruidModuleTest extends EasyMockSupport
{
  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  private static final String AZURE_ACCOUNT_NAME;
  private static final String AZURE_ACCOUNT_KEY;
  private static final String AZURE_SHARED_ACCESS_TOKEN;
  private static final String AZURE_CONTAINER;
  private static final String AZURE_PREFIX;
  private static final int AZURE_MAX_LISTING_LENGTH;
  private static final String PATH = "path";
  private static final Iterable<URI> EMPTY_PREFIXES_ITERABLE = ImmutableList.of();
  private static final Properties PROPERTIES;

  private CloudObjectLocation cloudObjectLocation1;
  private CloudObjectLocation cloudObjectLocation2;
  private ListBlobItem blobItem1;
  private ListBlobItem blobItem2;
  private Injector injector;

  static {
    try {
      AZURE_ACCOUNT_NAME = "azureAccount1";
      AZURE_ACCOUNT_KEY = Base64.getUrlEncoder()
                                .encodeToString("azureKey1".getBytes(StandardCharsets.UTF_8));
      AZURE_SHARED_ACCESS_TOKEN = "dummyToken";
      AZURE_CONTAINER = "azureContainer1";
      AZURE_PREFIX = "azurePrefix1";
      AZURE_MAX_LISTING_LENGTH = 10;
      PROPERTIES = initializePropertes();
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Before
  public void setup()
  {
    cloudObjectLocation1 = createMock(CloudObjectLocation.class);
    cloudObjectLocation2 = createMock(CloudObjectLocation.class);
    blobItem1 = createMock(ListBlobItem.class);
    blobItem2 = createMock(ListBlobItem.class);
  }

  @Test
  public void testGetAzureAccountConfigExpectedConfig()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    AzureAccountConfig azureAccountConfig = injector.getInstance(AzureAccountConfig.class);

    Assert.assertEquals(AZURE_ACCOUNT_NAME, azureAccountConfig.getAccount());
    Assert.assertEquals(AZURE_ACCOUNT_KEY, azureAccountConfig.getKey());
  }

  @Test
  public void testGetAzureAccountConfigExpectedConfigWithSAS()
  {
    Properties properties = initializePropertes();
    properties.setProperty("druid.azure.sharedAccessStorageToken", AZURE_SHARED_ACCESS_TOKEN);
    properties.remove("druid.azure.key");

    injector = makeInjectorWithProperties(properties);
    AzureAccountConfig azureAccountConfig = injector.getInstance(AzureAccountConfig.class);

    Assert.assertEquals(AZURE_ACCOUNT_NAME, azureAccountConfig.getAccount());
    Assert.assertEquals(AZURE_SHARED_ACCESS_TOKEN, azureAccountConfig.getSharedAccessStorageToken());
  }

  @Test
  public void testGetAzureDataSegmentConfigExpectedConfig()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    AzureDataSegmentConfig segmentConfig = injector.getInstance(AzureDataSegmentConfig.class);

    Assert.assertEquals(AZURE_CONTAINER, segmentConfig.getContainer());
    Assert.assertEquals(AZURE_PREFIX, segmentConfig.getPrefix());
  }

  @Test
  public void testGetAzureInputDataConfigExpectedConfig()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    AzureInputDataConfig inputDataConfig = injector.getInstance(AzureInputDataConfig.class);

    Assert.assertEquals(AZURE_MAX_LISTING_LENGTH, inputDataConfig.getMaxListingLength());
  }

  @Test
  public void testGetBlobClientExpectedClient()
  {
    injector = makeInjectorWithProperties(PROPERTIES);

    Supplier<CloudBlobClient> cloudBlobClient = injector.getInstance(
        Key.get(new TypeLiteral<Supplier<CloudBlobClient>>(){})
    );
    StorageCredentials storageCredentials = cloudBlobClient.get().getCredentials();

    Assert.assertEquals(AZURE_ACCOUNT_NAME, storageCredentials.getAccountName());
  }

  @Test
  public void testGetAzureStorageContainerExpectedClient()
  {
    injector = makeInjectorWithProperties(PROPERTIES);

    Supplier<CloudBlobClient> cloudBlobClient = injector.getInstance(
        Key.get(new TypeLiteral<Supplier<CloudBlobClient>>(){})
    );
    StorageCredentials storageCredentials = cloudBlobClient.get().getCredentials();

    Assert.assertEquals(AZURE_ACCOUNT_NAME, storageCredentials.getAccountName());

    AzureStorage azureStorage = injector.getInstance(AzureStorage.class);
    Assert.assertSame(cloudBlobClient.get(), azureStorage.getCloudBlobClient());
  }

  @Test
  public void testGetAzureStorageContainerWithSASExpectedClient()
  {
    Properties properties = initializePropertes();
    properties.setProperty("druid.azure.sharedAccessStorageToken", AZURE_SHARED_ACCESS_TOKEN);
    properties.remove("druid.azure.key");

    injector = makeInjectorWithProperties(properties);

    Supplier<CloudBlobClient> cloudBlobClient = injector.getInstance(
        Key.get(new TypeLiteral<Supplier<CloudBlobClient>>(){})
    );

    AzureAccountConfig azureAccountConfig = injector.getInstance(AzureAccountConfig.class);
    Assert.assertEquals(AZURE_SHARED_ACCESS_TOKEN, azureAccountConfig.getSharedAccessStorageToken());

    AzureStorage azureStorage = injector.getInstance(AzureStorage.class);
    Assert.assertSame(cloudBlobClient.get(), azureStorage.getCloudBlobClient());
  }

  @Test
  public void testGetAzureByteSourceFactoryCanCreateAzureByteSource()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    AzureByteSourceFactory factory = injector.getInstance(AzureByteSourceFactory.class);
    Object object1 = factory.create("container1", "blob1");
    Object object2 = factory.create("container2", "blob2");
    Assert.assertNotNull(object1);
    Assert.assertNotNull(object2);
    Assert.assertNotSame(object1, object2);
  }

  @Test
  public void testGetAzureEntityFactoryCanCreateAzureEntity()
  {
    EasyMock.expect(cloudObjectLocation1.getBucket()).andReturn(AZURE_CONTAINER);
    EasyMock.expect(cloudObjectLocation2.getBucket()).andReturn(AZURE_CONTAINER);
    EasyMock.expect(cloudObjectLocation1.getPath()).andReturn(PATH);
    EasyMock.expect(cloudObjectLocation2.getPath()).andReturn(PATH);
    replayAll();

    injector = makeInjectorWithProperties(PROPERTIES);
    AzureEntityFactory factory = injector.getInstance(AzureEntityFactory.class);
    Object object1 = factory.create(cloudObjectLocation1);
    Object object2 = factory.create(cloudObjectLocation2);
    Assert.assertNotNull(object1);
    Assert.assertNotNull(object2);
    Assert.assertNotSame(object1, object2);
  }

  @Test
  public void testGetAzureCloudBlobIteratorFactoryCanCreateAzureCloudBlobIterator()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    AzureCloudBlobIteratorFactory factory = injector.getInstance(AzureCloudBlobIteratorFactory.class);
    Object object1 = factory.create(EMPTY_PREFIXES_ITERABLE, 10);
    Object object2 = factory.create(EMPTY_PREFIXES_ITERABLE, 10);
    Assert.assertNotNull(object1);
    Assert.assertNotNull(object2);
    Assert.assertNotSame(object1, object2);
  }

  @Test
  public void testGetAzureCloudBlobIterableFactoryCanCreateAzureCloudBlobIterable()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    AzureCloudBlobIterableFactory factory = injector.getInstance(AzureCloudBlobIterableFactory.class);
    AzureCloudBlobIterable object1 = factory.create(EMPTY_PREFIXES_ITERABLE, 10);
    AzureCloudBlobIterable object2 = factory.create(EMPTY_PREFIXES_ITERABLE, 10);
    Assert.assertNotNull(object1);
    Assert.assertNotNull(object2);
    Assert.assertNotSame(object1, object2);
  }

  @Test
  public void testGetListBlobItemDruidFactoryCanCreateListBlobItemDruid()
  {
    injector = makeInjectorWithProperties(PROPERTIES);
    ListBlobItemHolderFactory factory = injector.getInstance(ListBlobItemHolderFactory.class);
    ListBlobItemHolder object1 = factory.create(blobItem1);
    ListBlobItemHolder object2 = factory.create(blobItem2);
    Assert.assertNotNull(object1);
    Assert.assertNotNull(object2);
    Assert.assertNotSame(object1, object2);
  }

  @Test
  public void testSegmentKillerBoundSingleton()
  {
    Injector injector = makeInjectorWithProperties(PROPERTIES);
    OmniDataSegmentKiller killer = injector.getInstance(OmniDataSegmentKiller.class);
    Assert.assertTrue(killer.getKillers().containsKey(AzureStorageDruidModule.SCHEME));
    Assert.assertSame(
        AzureDataSegmentKiller.class,
        killer.getKillers().get(AzureStorageDruidModule.SCHEME).get().getClass()
    );
    Assert.assertSame(
        killer.getKillers().get(AzureStorageDruidModule.SCHEME).get(),
        killer.getKillers().get(AzureStorageDruidModule.SCHEME).get()
    );
  }

  @Test
  public void testBothAccountKeyAndSAStokenSet()
  {
    Properties properties = initializePropertes();
    properties.setProperty("druid.azure.sharedAccessStorageToken", AZURE_SHARED_ACCESS_TOKEN);
    expectedException.expect(ProvisionException.class);
    expectedException.expectMessage("Either set 'key' or 'sharedAccessStorageToken' in the azure config but not both");
    makeInjectorWithProperties(properties).getInstance(
        Key.get(new TypeLiteral<Supplier<CloudBlobClient>>()
        {
        })
    );
  }

  @Test
  public void testBothAccountKeyAndSAStokenUnset()
  {
    Properties properties = initializePropertes();
    properties.remove("druid.azure.key");
    expectedException.expect(ProvisionException.class);
    expectedException.expectMessage("Either set 'key' or 'sharedAccessStorageToken' in the azure config but not both");
    makeInjectorWithProperties(properties).getInstance(
        Key.get(new TypeLiteral<Supplier<CloudBlobClient>>()
        {
        })
    );
  }

  @Test
  public void testGetAzureUtilsWithDefaultProperties()
  {
    Properties properties = initializePropertes();
    AzureUtils utils = makeInjectorWithProperties(properties).getInstance(AzureUtils.class);
    String outputBlob = utils.maybeRemoveAzurePathPrefix("blob.core.windows.net/container/blob");
    Assert.assertEquals("container/blob", outputBlob);
  }

  @Test
  public void testGetAzureUtilsWithDefaultCustomBlobPath()
  {
    Properties properties = initializePropertes();
    properties.setProperty("druid.azure.endpointSuffix", "core.usgovcloudapi.net");
    AzureUtils utils = makeInjectorWithProperties(properties).getInstance(AzureUtils.class);
    String outputBlob = utils.maybeRemoveAzurePathPrefix("blob.core.usgovcloudapi.net/container/blob");
    Assert.assertEquals("container/blob", outputBlob);
  }

  private Injector makeInjectorWithProperties(final Properties props)
  {
    return Guice.createInjector(
        ImmutableList.of(
            new DruidGuiceExtensions(),
            new JacksonModule(),
            new Module()
            {
              @Override
              public void configure(Binder binder)
              {
                binder.bind(Validator.class).toInstance(Validation.buildDefaultValidatorFactory().getValidator());
                binder.bind(JsonConfigurator.class).in(LazySingleton.class);
                binder.bind(Properties.class).toInstance(props);
              }
            },
            new AzureStorageDruidModule()
        ));
  }

  private static Properties initializePropertes()
  {
    final Properties props = new Properties();
    props.put("druid.azure.account", AZURE_ACCOUNT_NAME);
    props.put("druid.azure.key", AZURE_ACCOUNT_KEY);
    props.put("druid.azure.container", AZURE_CONTAINER);
    props.put("druid.azure.prefix", AZURE_PREFIX);
    props.put("druid.azure.maxListingLength", String.valueOf(AZURE_MAX_LISTING_LENGTH));
    return props;
  }
}
