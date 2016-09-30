/**
 * Copyright 2015-2016 The OpenZipkin Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package zipkin.autoconfigure.storage.elasticsearch.aws;

import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;

public class AWSSignatureVersion4Test {
  @Rule
  public ExpectedException thrown = ExpectedException.none();
  @Rule
  public MockWebServer es = new MockWebServer();

  String region = "us-east-1";
  AWSCredentials.Provider credentials =
      () -> new AWSCredentials("access-key", "secret-key", null);

  AWSSignatureVersion4 signer = new AWSSignatureVersion4(region, "es", () -> credentials.get());

  OkHttpClient client = new OkHttpClient.Builder().addNetworkInterceptor(signer).build();

  @After
  public void close() throws IOException {
    client.dispatcher().executorService().shutdownNow();
  }

  @Test
  public void propagatesExceptionGettingCredentials() throws InterruptedException, IOException {
    // makes sure this isn't wrapped.
    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Unable to load AWS credentials from any provider in the chain");

    credentials = () -> {
      throw new IllegalStateException(
          "Unable to load AWS credentials from any provider in the chain");
    };

    client.newCall(new Request.Builder().url(es.url("/")).build()).execute();
  }

  @Test
  public void signsRequestsForRegionAndEsService() throws InterruptedException, IOException {
    es.enqueue(new MockResponse());

    client.newCall(new Request.Builder().url(es.url("/_template/zipkin_template")).build())
        .execute();

    RecordedRequest request = es.takeRequest();
    assertThat(request.getHeader("Authorization"))
        .startsWith("AWS4-HMAC-SHA256 Credential=" + credentials.get().accessKey)
        .contains(region + "/es/aws4_request"); // for the region and service
  }
}
