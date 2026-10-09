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

package org.apache.druid.testing.embedded.s3;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import org.apache.druid.common.aws.AWSModule;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.storage.s3.S3StorageDruidModule;
import org.apache.druid.testing.embedded.EmbeddedDruidCluster;
import org.apache.druid.testing.embedded.TestcontainerResource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * An S3-compatible storage container resource for use in embedded tests as deep storage.
 * Runs <a href="https://github.com/rustfs/rustfs">RustFS</a> and configures Druid's S3 connector to use it.
 */
public class S3StorageResource extends TestcontainerResource<GenericContainer<?>>
{
  private static final DockerImageName IMAGE = DockerImageName.parse("rustfs/rustfs:1.0.0");
  private static final int S3_PORT = 9000;
  private static final String DEFAULT_BUCKET = "druid-deep-storage";
  private static final String DEFAULT_BASE_KEY = "druid/segments";
  private static final String ACCESS_KEY = "rustfsadmin";
  private static final String SECRET_KEY = "rustfsadmin";

  private final String bucket;
  private final String baseKey;
  private AmazonS3 s3Client;

  public S3StorageResource()
  {
    this(DEFAULT_BUCKET, DEFAULT_BASE_KEY);
  }

  public S3StorageResource(String bucket, String baseKey)
  {
    this.bucket = bucket;
    this.baseKey = baseKey;
  }

  @Override
  protected GenericContainer<?> createContainer()
  {
    return new GenericContainer<>(IMAGE)
        .withExposedPorts(S3_PORT)
        .withEnv("RUSTFS_ACCESS_KEY", getAccessKey())
        .withEnv("RUSTFS_SECRET_KEY", getSecretKey())
        .waitingFor(Wait.forHttp("/health/ready").forPort(S3_PORT));
  }

  @Override
  public void onStarted(EmbeddedDruidCluster cluster)
  {
    s3Client = createS3Client();
    s3Client.createBucket(bucket);

    cluster.addExtension(S3StorageDruidModule.class);
    cluster.addExtension(AWSModule.class);

    // Configure storage bucket and base key
    cluster.addCommonProperty("druid.storage.type", "s3");
    cluster.addCommonProperty("druid.storage.bucket", getBucket());
    cluster.addCommonProperty("druid.storage.baseKey", getBaseKey());

    // Configure indexer logs
    cluster.addCommonProperty("druid.indexer.logs.type", "s3");
    cluster.addCommonProperty("druid.indexer.logs.s3Bucket", getBucket());
    cluster.addCommonProperty("druid.indexer.logs.s3Prefix", "druid/indexing-logs");

    // Configure S3 connection properties
    cluster.addCommonProperty("druid.s3.endpoint.url", getEndpointUrl());
    cluster.addCommonProperty("druid.s3.accessKey", getAccessKey());
    cluster.addCommonProperty("druid.s3.secretKey", getSecretKey());
    cluster.addCommonProperty("druid.s3.enablePathStyleAccess", "true");
    cluster.addCommonProperty("druid.s3.protocol", "http");
  }

  public String getBucket()
  {
    return bucket;
  }

  public String getBaseKey()
  {
    return baseKey;
  }

  public String getAccessKey()
  {
    return ACCESS_KEY;
  }

  public String getSecretKey()
  {
    return SECRET_KEY;
  }

  public String getEndpointUrl()
  {
    ensureRunning();
    return StringUtils.format("http://%s:%d", getContainer().getHost(), getContainer().getMappedPort(S3_PORT));
  }

  public AmazonS3 getS3Client()
  {
    ensureRunning();
    return s3Client;
  }

  private AmazonS3 createS3Client()
  {
    return AmazonS3Client
        .builder()
        .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(getEndpointUrl(), "us-east-1"))
        .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(getAccessKey(), getSecretKey())))
        .withPathStyleAccessEnabled(true)
        .build();
  }
}
