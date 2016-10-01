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
package zipkin.storage.elasticsearch.http;

import com.google.common.base.Joiner;
import com.google.common.util.concurrent.ListenableFuture;
import com.squareup.moshi.JsonWriter;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import okio.Buffer;

// See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
// exposed to re-use for testing writes of dependency links
abstract class HttpBulkIndexer<T> {
  static final MediaType APPLICATION_JSON = MediaType.parse("application/json");

  // Immutable fields
  final HttpClient client;
  final String typeName;
  final String tag;

  // Mutated for each call to add
  final Buffer body = new Buffer();
  final Set<String> indices = new LinkedHashSet<>();

  HttpBulkIndexer(HttpClient client, String typeName) {
    this.client = client;
    this.typeName = typeName;
    this.tag = "index-" + typeName;
  }

  void add(String index, T object, String id) throws IOException {
    writeIndexMetadata(index, id);
    writeDocument(object);

    if (client.flushOnWrites) indices.add(index);
  }

  void writeIndexMetadata(String index, String id) throws IOException {
    JsonWriter writer = JsonWriter.of(body);
    writer.beginObject().name("index").beginObject();
    writer.name("_index").value(index);
    writer.name("_type").value(typeName);
    writer.name("_id").value(id);
    writer.endObject().endObject();
    body.writeByte('\n');
  }

  void writeDocument(T object) throws IOException {
    body.write(toJsonBytes(object));
    body.writeByte('\n');
  }

  abstract byte[] toJsonBytes(T object);

  /** Creates a bulk request when there is more than one object to store */
  public ListenableFuture<Void> execute() { // public to allow interface retrofit
    Call post = client.http.newCall(new Request.Builder()
        .url(client.baseUrl.resolve("/_bulk"))
        .post(RequestBody.create(APPLICATION_JSON, body.readByteString()))
        .tag(tag).build());

    return new CallbackListenableFuture<Void>(post) {
      @Override Void convert(ResponseBody responseBody) throws IOException {
        if (!indices.isEmpty()) {
          client.flush(Joiner.on(',').join(indices));
        }
        return null;
      }
    }.enqueue();
  }
}
