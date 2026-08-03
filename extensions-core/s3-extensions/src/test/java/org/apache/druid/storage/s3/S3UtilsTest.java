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

package org.apache.druid.storage.s3;

import org.apache.druid.common.aws.AWSClientConfig;
import org.easymock.Capture;
import org.easymock.CaptureType;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.LegacyMd5Plugin;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClientBuilder;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class S3UtilsTest
{
  @Test
  public void testConfigureLegacyMd5Disabled()
  {
    final S3ClientBuilder s3ClientBuilder = S3Client.builder();

    S3Utils.configureLegacyMd5(s3ClientBuilder, new AWSClientConfig());

    Assert.assertTrue(s3ClientBuilder.plugins().isEmpty());
  }

  @Test
  public void testConfigureLegacyMd5EnabledForSyncAndAsyncClients()
  {
    final AWSClientConfig clientConfig = EasyMock.createMock(AWSClientConfig.class);
    EasyMock.expect(clientConfig.isEnableLegacyMd5()).andReturn(true).times(2);
    EasyMock.replay(clientConfig);
    final S3ClientBuilder s3ClientBuilder = S3Client.builder();
    final S3AsyncClientBuilder s3AsyncClientBuilder = S3AsyncClient.builder();

    S3Utils.configureLegacyMd5(s3ClientBuilder, clientConfig);
    S3Utils.configureLegacyMd5(s3AsyncClientBuilder, clientConfig);

    Assert.assertEquals(1, s3ClientBuilder.plugins().size());
    Assert.assertEquals(1, s3AsyncClientBuilder.plugins().size());
    Assert.assertTrue(s3ClientBuilder.plugins().get(0) instanceof LegacyMd5Plugin);
    Assert.assertTrue(s3AsyncClientBuilder.plugins().get(0) instanceof LegacyMd5Plugin);
    EasyMock.verify(clientConfig);
  }

  @Test
  public void testRetryWithIOExceptions()
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    Assert.assertThrows(
        IOException.class,
        () -> S3Utils.retryS3Operation(
            () -> {
              count.incrementAndGet();
              throw new IOException("hmm");
            },
            maxRetries
        ));
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testRetryWith4XXErrors()
  {
    final AtomicInteger count = new AtomicInteger();
    Assert.assertThrows(
        IOException.class,
        () -> S3Utils.retryS3Operation(
            () -> {
              if (count.incrementAndGet() >= 2) {
                return "hey";
              } else {
                S3Exception s3Exception = (S3Exception) S3Exception.builder()
                    .message("a 403 s3 exception")
                    .statusCode(403)
                    .build();
                throw new IOException(s3Exception);
              }
            },
            3
        ));
    Assert.assertEquals(1, count.get());
  }

  @Test
  public void testRetryWith5XXErrorsNotExceedingMaxRetries() throws Exception
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    S3Utils.retryS3Operation(
        () -> {
          if (count.incrementAndGet() >= maxRetries) {
            return "hey";
          } else {
            S3Exception s3Exception = (S3Exception) S3Exception.builder()
                .message("a 5xx s3 exception")
                .statusCode(500)
                .build();
            throw new IOException(s3Exception);
          }
        },
        maxRetries
    );
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testRetryWith5XXErrorsExceedingMaxRetries()
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    Assert.assertThrows(
        IOException.class,
        () -> S3Utils.retryS3Operation(
            () -> {
              if (count.incrementAndGet() > maxRetries) {
                return "hey";
              } else {
                S3Exception s3Exception = (S3Exception) S3Exception.builder()
                    .message("a 5xx s3 exception")
                    .statusCode(500)
                    .build();
                throw new IOException(s3Exception);
              }
            },
            maxRetries
        )
    );
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testRetryWithSdkClientException() throws Exception
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    S3Utils.retryS3Operation(
        () -> {
          if (count.incrementAndGet() >= maxRetries) {
            return "hey";
          } else {
            throw SdkClientException.builder()
                .message(
                    "Unable to find a region via the region provider chain. "
                    + "Must provide an explicit region in the builder or setup environment to supply a region."
                )
                .build();
          }
        },
        maxRetries
    );
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testRetryWithS3InternalError() throws Exception
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    S3Utils.retryS3Operation(
        () -> {
          if (count.incrementAndGet() >= maxRetries) {
            return "donezo";
          } else {
            S3Exception s3Exception = (S3Exception) S3Exception.builder()
                .message("We encountered an internal error. Please try again. (Service: Amazon S3; Status Code: 200; Error Code: InternalError; Request ID: some-id)")
                .statusCode(200)
                .build();
            throw s3Exception;
          }
        },
        maxRetries
    );
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testRetryWithS3SlowDown() throws Exception
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    S3Utils.retryS3Operation(
        () -> {
          if (count.incrementAndGet() >= maxRetries) {
            return "success";
          } else {
            S3Exception s3Exception = (S3Exception) S3Exception.builder()
                .message("Please reduce your request rate. SlowDown")
                .statusCode(200)
                .build();
            throw s3Exception;
          }
        },
        maxRetries
    );
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testNoRetryWithS3InternalErrorNon200Status()
  {
    final AtomicInteger count = new AtomicInteger();
    Assert.assertThrows(
        Exception.class,
        () -> S3Utils.retryS3Operation(
            () -> {
              count.incrementAndGet();
              S3Exception s3Exception = (S3Exception) S3Exception.builder()
                  .message("InternalError occurred")
                  .statusCode(403)
                  .build();
              throw s3Exception;
            },
            3
        )
    );
    Assert.assertEquals(1, count.get());
  }

  @Test
  public void testNoRetryWithS3SlowDownNon200Status()
  {
    final AtomicInteger count = new AtomicInteger();
    Assert.assertThrows(
        Exception.class,
        () -> S3Utils.retryS3Operation(
            () -> {
              count.incrementAndGet();
              S3Exception s3Exception = (S3Exception) S3Exception.builder()
                  .message("SlowDown message")
                  .statusCode(404)
                  .build();
              throw s3Exception;
            },
            3
        )
    );
    Assert.assertEquals(1, count.get());
  }

  @Test
  public void testRetryWithS3Status200ButDifferentError()
  {
    final AtomicInteger count = new AtomicInteger();
    Assert.assertThrows(
        Exception.class,
        () -> S3Utils.retryS3Operation(
            () -> {
              count.incrementAndGet();
              S3Exception s3Exception = (S3Exception) S3Exception.builder()
                  .message("Some other error message")
                  .statusCode(200)
                  .build();
              throw s3Exception;
            },
            3
        )
    );
    Assert.assertEquals(1, count.get());
  }

  @Test
  public void testDeleteBucketKeysSuccess() throws Exception
  {
    ServerSideEncryptingAmazonS3 s3Client = EasyMock.createMock(ServerSideEncryptingAmazonS3.class);
    DeleteObjectsResponse successResponse = DeleteObjectsResponse.builder().build();
    EasyMock.expect(s3Client.deleteObjects(EasyMock.anyObject(DeleteObjectsRequest.class)))
            .andReturn(successResponse)
            .once();
    EasyMock.replay(s3Client);

    List<ObjectIdentifier> keys = List.of(
        ObjectIdentifier.builder().key("a").build(),
        ObjectIdentifier.builder().key("b").build()
    );
    S3Utils.deleteBucketKeys(s3Client, "bucket", keys, 3);
    EasyMock.verify(s3Client);
  }

  @Test
  public void testDeleteBucketKeysRetriesOnlyFailedKeys() throws Exception
  {
    ServerSideEncryptingAmazonS3 s3Client = EasyMock.createMock(ServerSideEncryptingAmazonS3.class);

    // First call: key "b" fails
    DeleteObjectsResponse firstResponse = DeleteObjectsResponse.builder()
        .errors(S3Error.builder().key("b").code("InternalError").message("err").build())
        .build();
    // Second call (retry): only "b" is sent, succeeds
    DeleteObjectsResponse secondResponse = DeleteObjectsResponse.builder().build();

    Capture<DeleteObjectsRequest> capturedRequests = Capture.newInstance(CaptureType.ALL);
    EasyMock.expect(s3Client.deleteObjects(EasyMock.capture(capturedRequests)))
            .andReturn(firstResponse)
            .andReturn(secondResponse);
    EasyMock.replay(s3Client);

    List<ObjectIdentifier> keys = List.of(
        ObjectIdentifier.builder().key("a").build(),
        ObjectIdentifier.builder().key("b").build()
    );
    S3Utils.deleteBucketKeys(s3Client, "bucket", keys, 3);
    EasyMock.verify(s3Client);

    // First request should have both keys
    List<String> firstKeys = capturedRequests.getValues().get(0).delete().objects()
                                 .stream().map(ObjectIdentifier::key).collect(Collectors.toList());
    Assert.assertEquals(List.of("a", "b"), firstKeys);

    // Second request should only have the failed key
    List<String> secondKeys = capturedRequests.getValues().get(1).delete().objects()
                                  .stream().map(ObjectIdentifier::key).collect(Collectors.toList());
    Assert.assertEquals(List.of("b"), secondKeys);
  }

  @Test
  public void testDeleteBucketKeysThrowsAfterAllRetriesExhausted()
  {
    ServerSideEncryptingAmazonS3 s3Client = EasyMock.createMock(ServerSideEncryptingAmazonS3.class);

    DeleteObjectsResponse errorResponse = DeleteObjectsResponse.builder()
        .errors(S3Error.builder().key("a").code("InternalError").message("err").build())
        .build();
    EasyMock.expect(s3Client.deleteObjects(EasyMock.anyObject(DeleteObjectsRequest.class)))
            .andReturn(errorResponse)
            .anyTimes();
    EasyMock.replay(s3Client);

    List<ObjectIdentifier> keys = List.of(ObjectIdentifier.builder().key("a").build());
    S3MultiObjectDeleteException thrown = Assert.assertThrows(
        S3MultiObjectDeleteException.class,
        () -> S3Utils.deleteBucketKeys(s3Client, "bucket", keys, 2)
    );
    Assert.assertEquals(1, thrown.getErrors().size());
    Assert.assertEquals("a", thrown.getErrors().get(0).key());
    EasyMock.verify(s3Client);
  }

  @Test
  public void testDeleteBucketKeysPartialFailureRetriesAlsoFail()
  {
    ServerSideEncryptingAmazonS3 s3Client = EasyMock.createMock(ServerSideEncryptingAmazonS3.class);

    // First call: key "b" fails; second call (retry of "b"): still fails
    DeleteObjectsResponse firstResponse = DeleteObjectsResponse.builder()
        .errors(S3Error.builder().key("b").code("InternalError").message("err").build())
        .build();
    DeleteObjectsResponse retryResponse = DeleteObjectsResponse.builder()
        .errors(S3Error.builder().key("b").code("InternalError").message("err").build())
        .build();

    EasyMock.expect(s3Client.deleteObjects(EasyMock.anyObject(DeleteObjectsRequest.class)))
            .andReturn(firstResponse)
            .andReturn(retryResponse);
    EasyMock.replay(s3Client);

    List<ObjectIdentifier> keys = List.of(
        ObjectIdentifier.builder().key("a").build(),
        ObjectIdentifier.builder().key("b").build()
    );
    S3MultiObjectDeleteException thrown = Assert.assertThrows(
        S3MultiObjectDeleteException.class,
        () -> S3Utils.deleteBucketKeys(s3Client, "bucket", keys, 1)
    );
    Assert.assertEquals(1, thrown.getErrors().size());
    Assert.assertEquals("b", thrown.getErrors().get(0).key());
    EasyMock.verify(s3Client);
  }

  @Test
  public void testRetryWithS3MultiObjectDeleteException() throws Exception
  {
    final int maxRetries = 3;
    final AtomicInteger count = new AtomicInteger();
    S3Utils.retryS3Operation(
        () -> {
          if (count.incrementAndGet() >= maxRetries) {
            return "success";
          } else {
            throw new S3MultiObjectDeleteException(
                List.of(S3Error.builder().key("x").code("InternalError").message("err").build())
            );
          }
        },
        maxRetries
    );
    Assert.assertEquals(maxRetries, count.get());
  }

  @Test
  public void testBucketNormalizationForMRAP()
  {
    String bucket = "arn:aws:s3::123456789123:accesspoint/bucket.mrap";
    Assert.assertEquals("arn:aws:s3::123456789123:accesspoint:bucket.mrap", S3Utils.normalizeBucketName(bucket));
  }

  @Test
  public void testBucketNormalizationForRegional()
  {
    String bucket = "arn:aws:s3:us-east-1:123456789123:accesspoint/bucket";
    Assert.assertEquals("arn:aws:s3:us-east-1:123456789123:accesspoint:bucket", S3Utils.normalizeBucketName(bucket));
  }

  @Test
  public void testAlreadyNormalizedBucket()
  {
    String bucket = "arn:aws:s3::123456789123:accesspoint:bucket.mrap";
    Assert.assertEquals(bucket, S3Utils.normalizeBucketName(bucket));
  }

  @Test
  public void testNonS3Bucket()
  {
    String bucket = "bucket/subpath";
    Assert.assertEquals(bucket, S3Utils.normalizeBucketName(bucket));
  }
}
