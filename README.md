# oss-go-fake

A local stand-in for [Alibaba Cloud OSS](https://www.alibabacloud.com/product/object-storage-service). It speaks the native OSS REST protocol, checks V1 and V4 signatures strictly, and keeps everything in a plain directory, so development and tests run against real SDKs without a cloud bill.

- Native OSS protocol, not an S3 compatibility layer. Official SDKs work unchanged.
- V1 and V4 signatures, in the `Authorization` header and in presigned URLs. A request with a wrong signature fails here the way it fails on OSS.
- A single static binary. Run it from the command line, as a systemd service, in Docker, or from a test launcher.
- Data lives in one directory. Mount it as a volume and it survives restarts.

It is built for development and testing, around ten thousand objects. It is not a production object store.

## Quick start

### Docker

```sh
mkdir data && sudo chown 65532:65532 data
docker run --rm -p 8080:8080 -v "$PWD/data:/data" ghcr.io/dofunc/oss-go-fake:latest \
  serve --data-dir /data --access-key fake-ak:fake-sk --bucket example
```

The image runs as the non-root user 65532, so the mounted directory must be writable by that uid. See [examples/docker-compose.yml](examples/docker-compose.yml) and [examples/kubernetes/oss-fake.yaml](examples/kubernetes/oss-fake.yaml).

### Binary, started on the spot

Download the binary for your platform from the [releases](https://github.com/dofunc/oss-go-fake/releases) and verify it against `checksums.txt`:

```sh
chmod +x oss-go-fake-linux-amd64
./oss-go-fake-linux-amd64 serve --data-dir ./data --access-key fake-ak:fake-sk --bucket example
# oss-go-fake ready on [::]:8080
```

Once listening, it prints `oss-go-fake ready on <addr>` to standard output. Launchers can wait for that line. Logs go to standard error as JSON, one line per request.

### Binary as a systemd service

[examples/systemd/oss-go-fake.service](examples/systemd/oss-go-fake.service) runs the binary under a dynamic service user with its data in `/var/lib/oss-go-fake`. The install steps are at the top of the file.

### Point a client at it

Use path-style addressing (or configure `--domain` for virtual-hosted style), plain HTTP, and the region the server checks:

```go
cfg := oss.LoadDefaultConfig().
	WithCredentialsProvider(credentials.NewStaticCredentialsProvider("fake-ak", "fake-sk")).
	WithRegion("cn-hangzhou").
	WithEndpoint("127.0.0.1:8080").
	WithUsePathStyle(true).
	WithDisableSSL(true)
client := oss.NewClient(cfg)
```

```java
ClientBuilderConfiguration conf = new ClientBuilderConfiguration();
conf.setSignatureVersion(SignVersion.V4);
conf.setSLDEnabled(true); // path-style: the bucket goes in the path
OSS client = OSSClientBuilder.create()
    .endpoint("http://127.0.0.1:8080")
    .credentialsProvider(new DefaultCredentialProvider("fake-ak", "fake-sk"))
    .clientConfiguration(conf)
    .region("cn-hangzhou")
    .build();
```

## Configuration

Every setting is available as a flag and as a key of a YAML file given with `--config`. Flags win over the file.

```
oss-go-fake serve [flags]
oss-go-fake version
```

| Flag | Config key | Default | Meaning |
|---|---|---|---|
| `--config` | | | YAML config file |
| `--listen` | `listen` | `:8080` | Listen address |
| `--data-dir` | `data-dir` | `./data` | Data root directory |
| `--domain` | `domain` | empty | Base domain of virtual-hosted requests. Empty accepts path-style only |
| `--region` | `region` | `cn-hangzhou` | Region V4 credential scopes must name |
| `--access-key` | `access-keys` | | `AK:SK`, repeatable. At least one is required |
| `--bucket` | `buckets` | | `name[:private\|public-read]`, repeatable. Default ACL is `private` |
| `--protocol` | `protocols` | `oss` | Enabled protocols. Only `oss` in this release |
| `--log-level` | `log-level` | `info` | `debug`, `info`, `warn` or `error` |

See [examples/config.yaml](examples/config.yaml) for a full file. Merge rules:

- Scalars: the flag, if given, replaces the file value.
- `access-keys`: merged by `id`. A flag with the same id replaces the secret.
- `buckets`: merged by `name`. A flag with the same name replaces the ACL. CORS rules come from the file only.
- Unknown keys in the file are errors.

Configuration errors exit with code 2. At startup, every declared bucket that does not exist is created, and every existing one gets the configured ACL. `SIGINT` or `SIGTERM` stops accepting connections and waits up to 10 seconds for in-flight requests.

## Supported API

| Area | Operations |
|---|---|
| Service | ListBuckets |
| Bucket | PutBucket, DeleteBucket, GetBucketInfo, ListObjects, ListObjectsV2, DeleteMultipleObjects |
| Object | PutObject, GetObject, HeadObject, GetObjectMeta, CopyObject, DeleteObject |
| CORS | `OPTIONS` preflight and CORS response headers, from per-bucket rules in the config file |

Details that follow OSS:

- ETag is the upper-case hex MD5 in double quotes, and a copy keeps the source ETag.
- `Content-MD5` is verified. A mismatch is `400 InvalidDigest`, and nothing is stored.
- `x-oss-forbid-overwrite: true` returns `409 FileAlreadyExists` for PutObject and CopyObject.
- CopyObject works across buckets, with `x-oss-metadata-directive` set to `COPY` or `REPLACE`.
- Range follows OSS: a range that cannot be satisfied returns the whole object. With `x-oss-range-behavior: standard`, an end past the object is clamped, and a start past it fails with `416 InvalidRange`.
- `response-content-type` and the other `response-*` parameters override GetObject headers.
- With a delimiter, `max-keys` counts objects and common prefixes together. `encoding-type=url` is honoured.
- `public-read` opens object reads (GetObject, HeadObject, GetObjectMeta) to anonymous callers. Listing and bucket operations always need a signature.
- CORS preflight needs no signature and ignores the ACL: only the bucket's CORS rules decide.
- Errors are OSS error XML with `x-oss-request-id`. Every error also carries the XML base64 encoded in `x-oss-err`, which is how SDKs read errors of `HEAD` requests.

Anything else, including multipart upload, append, ACL and tagging sub-resources, lifecycle, versioning, server-side encryption, image processing (`x-oss-process`) and STS tokens, answers `501 NotImplemented`. S3-signed requests answer `501` with `S3 protocol is not enabled`. The protocol layer has room for S3, but it is not implemented.

## Signatures

| Version | Header | URL |
|---|---|---|
| V1 | `Authorization: OSS <ak>:<signature>` (HMAC-SHA1) | `OSSAccessKeyId`, `Expires`, `Signature` |
| V4 | `Authorization: OSS4-HMAC-SHA256 Credential=...` (HMAC-SHA256) | `x-oss-signature-version`, `x-oss-credential`, `x-oss-date`, `x-oss-expires`, `x-oss-signature` |

- Header-signed requests must be within 15 minutes of the server clock, or they fail with `403 RequestTimeTooSkewed`.
- Expired URLs fail with `403 AccessDenied`.
- V4 accepts only `x-oss-content-sha256: UNSIGNED-PAYLOAD`. The credential scope must name the configured region.
- On `SignatureDoesNotMatch`, the error XML carries the server's `StringToSign` (and `CanonicalRequest` for V4) to diff against your client's.
- The canonicalization is checked against the test vectors published with the official Go SDK.

## Storage layout

```
<data-dir>/
  .tmp/                                  writes in progress, cleared at startup
  <bucket>/
    bucket.json                          name, ACL, creation time
    objects/<h2>/<sha256(key)>.json      object metadata
    objects/<h2>/<sha256(key)>.<id>      object data, a new file per write
```

Object names never become paths. Objects are stored under the SHA-256 of their name, so `a` and `a/b` coexist, names up to 1023 bytes fit, `../x` is just a name, and case-insensitive file systems keep `A` and `a` apart.

A write streams to `.tmp/`, moves into place, and commits by renaming the metadata file over the old one. Readers see the old object or the new one, never a mix. Listing reads every metadata file of the bucket, so it slows down linearly with the object count. One process per data directory.

## Known differences from OSS

- One tenant. Every configured access key owns every bucket. There are no RAM policies, bucket policies or STS.
- ACLs are `private` and `public-read`, per bucket only.
- `EC` in error responses is always `0000-00000000`. Real OSS has a specific EC per failure.
- No `x-oss-hash-crc64ecma` header. SDKs skip their CRC check when it is absent.
- Conditional headers (`If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, and the `x-oss-copy-source-if-*` family) are ignored.
- `Last-Modified` has one-second precision.
- ListBuckets returns every bucket and ignores `prefix`, `marker` and `max-keys`. The endpoints in bucket info echo the request `Host`.

## License

[Apache-2.0](LICENSE)
