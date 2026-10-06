# caddy-s3-proxy

`s3_proxy` is a [Caddy](https://caddyserver.com) HTTP handler that serves objects straight out of an S3-compatible bucket: Cloudflare R2, AWS S3, MinIO, Garage, Backblaze B2 or anything else that speaks the S3 API with Signature Version 4. Each request becomes **exactly one signed `GET` or `HEAD`** to the bucket, with the client's `Range` passed through, and the body is streamed back as it arrives. Nothing is buffered, retried, listed or cached by this module; put Caddy's own `cache` or any caching module in front if you want caching.

It needs Caddy 2.11.7 or later and Go 1.26 or later to build. MIT licensed.

## Why another S3 module

Serving a bucket through Caddy is a common need, and the modules that exist for it are either the wrong shape or no longer maintained.

**Filesystem modules are the wrong shape.** The `caddy.fs` modules such as `caddy-fs-s3` plug a bucket in as a filesystem under `file_server`. That reuses Caddy's file serving, which is attractive, but `file_server` was written for local disks and treats every call as free. Traced against Caddy 2.11.7 and the `s3fs` library underneath, one request for one object becomes:

| What `file_server` does | What the bucket sees |
|---|---|
| `Stat` to learn the size and modification time | `HeadObject` |
| `Open` the file | `GetObject`, body discarded |
| `http.ServeContent` seeks to the end and back to find the size | `GetObject` with `Range: bytes=0-` |
| every client `Range` request, such as a video player seeking | one more `GetObject` |
| a missing object: `Stat` fails, so it probes for a directory | `ListObjects`, the expensive operation class |

Three to four billed operations where one would do, a listing for every 404, and no way to pass the client's `Range` through because `fs.FS` has no such concept. This is inherent to the interface, not a bug in any implementation of it: `file_server` always calls `Stat` then `Open` then seeks, and nothing in `fs.FS` carries a byte range. The `caddy.fs` modules also authenticate through the AWS SDK's default credential chain, which quietly reads environment variables, profile files and instance metadata, and will silently fall back to the SDK's own endpoint lookup when yours is misconfigured.

**The proxy modules are outdated.** The handler-style module `lindenlab/caddy-s3-proxy`, which is the right shape, was last released in January 2021 against Caddy 2.3 and the v1 AWS SDK, which went end-of-support in July 2025. Its several forks on GitHub carry the same dependencies forward. None of them build cleanly against a current Caddy without patching, and all pull in a large SDK for what is, at bottom, one HTTP request with a signature.

This module is a few hundred lines: a SigV4 signer, a request builder and a response copier, with no dependency beyond Caddy itself. It is what an nginx `proxy_pass` with a Lua signer did, written as a Caddy handler.

## Caddyfile

```caddyfile
s3_proxy [<matcher>] {
    endpoint   <url>
    bucket     <name>
    region     <region>
    access_key <id>
    secret_key <secret>
    virtual_hosted
    dial_timeout            <duration>
    response_header_timeout <duration>
}
```

The directive takes no inline arguments besides a matcher. It is ordered right after `reverse_proxy` and is terminal: nothing after it in the same route runs.

| Option | Required | Default | Meaning |
|---|---|---|---|
| `endpoint` | yes | | URL of the S3 service: scheme and host, with an optional port, and no path. For R2: `https://<account>.r2.cloudflarestorage.com`. For AWS: `https://s3.<region>.amazonaws.com`. An empty or missing endpoint is a configuration error, never a fallback to something else. |
| `bucket` | yes | | Bucket name. The bucket comes from here, not from the request path. |
| `region` | yes | | Signing region. `auto` for R2, `us-east-1` or similar for AWS, whatever your server expects otherwise. |
| `access_key` | yes | | Access key ID. |
| `secret_key` | yes | | Secret access key. |
| `virtual_hosted` | no | off | Send `https://<bucket>.<endpoint host>/<key>` instead of `<endpoint>/<bucket>/<key>`. Path style, the default, works everywhere; some providers also accept or prefer the virtual-hosted form. |
| `dial_timeout` | no | `10s` | Bound on connecting, and separately on the TLS handshake. |
| `response_header_timeout` | no | `30s` | Bound on the wait for the response headers after the request is sent. |

The object key is the request path after any `rewrite`, without its leading slash. The query string is ignored. A minimal site:

```caddyfile
images.example.com {
    s3_proxy {
        endpoint   https://<account>.r2.cloudflarestorage.com
        bucket     images
        region     auto
        access_key {$AWS_ACCESS_KEY_ID}
        secret_key {$AWS_SECRET_ACCESS_KEY}
    }
}
```

A URL prefix that is not part of the key, with a cache in front:

```caddyfile
cdn.example.com {
    handle /img/* {
        header Cache-Control "public, max-age=31536000"
        cache
        rewrite /img/* /images{path}
        s3_proxy {
            endpoint   {$S3_ENDPOINT}
            bucket     {$S3_BUCKET}
            region     {$S3_REGION}
            access_key {$AWS_ACCESS_KEY_ID}
            secret_key {$AWS_SECRET_ACCESS_KEY}
        }
    }
}
```

The equivalent JSON handler is:

```json
{
    "handler": "s3_proxy",
    "endpoint": "https://<account>.r2.cloudflarestorage.com",
    "bucket": "images",
    "region": "auto",
    "access_key": "...",
    "secret_key": "...",
    "virtual_hosted": false,
    "dial_timeout": "10s",
    "response_header_timeout": "30s"
}
```

### Credentials and the environment

The module **never reads the environment**: no `os.Getenv`, no AWS SDK, no shared credential files, no instance metadata, no proxy settings. Every option is whatever string the configuration holds. `{$VAR}` in a Caddyfile is substituted by the Caddyfile adapter before the module sees anything; `{env.VAR}` is resolved once at provisioning by Caddy's replacer. Either way, the configuration names the variable, and nothing else is consulted. A test fails the build if a source file of the module ever touches the environment.

As with any Caddy module that holds a secret, `secret_key` is part of the JSON configuration and visible through the admin API. It is never logged, nor is the `Authorization` header.

## What is sent and what comes back

Per request:

1. Methods other than `GET` and `HEAD` get `405` with `Allow: GET, HEAD`, without contacting the bucket.
2. An empty key, or one ending in `/`, gets `404` without contacting the bucket.
3. One request goes to the bucket, carrying only `Host`, `Range` (if the client sent one, with surrounding and repeated spaces normalised as SigV4 requires), `x-amz-date`, `x-amz-content-sha256` and `Authorization`. No other client header, no query string, no body. The signature is SigV4 for service `s3`, covering the `Range` header when present, with the key percent-encoded per the S3 canonical rules so that the signed path and the path on the wire are the same string.
4. The status code comes back unchanged (`200`, `206`, `404`, `403`, `416`, `5xx`) with only these headers: `Content-Type`, `Content-Length`, `Content-Range`, `Accept-Ranges`, `ETag`, `Last-Modified`, `Content-Encoding`, `Content-Disposition`, `Cache-Control`, `Expires`. Everything else, `x-amz-*` and `cf-*` included, is dropped. A header already set earlier in the route, by a `header` directive for instance, is kept and the bucket's value dropped, as `file_server` does. That is how a wrong `Content-Type` stored with an object is corrected from the configuration.
5. The body is streamed in 32 KiB chunks. Nothing is buffered, retried or cached.

Failures before the headers are written become Caddy handler errors, so `handle_errors` applies: `502` for a connection, TLS or reset failure and for a request whose context ended, `504` when the bucket accepted the request and the response headers did not arrive in time. If the upstream connection drops mid-body, the handler panics with `http.ErrAbortHandler`, exactly as `reverse_proxy` does, so the client connection is cut and a cache in front discards the partial download instead of storing it.

### The one-request guarantee

The test suite runs every case against a fake S3 server that verifies each signature, refuses any header outside the signed set, and counts requests per method and path. Each test asserts that count is exactly one, or zero where the handler answers by itself. There is no `HEAD` before a `GET`, no seek, no listing on a miss. Test coverage of the module is 100% of statements.

## Building

```sh
xcaddy build --with github.com/Meow/caddy-s3-proxy@1.0.0
```

Tags carry no `v` prefix.

## Migrating from a filesystem module

Remove the global `filesystem` block and swap `file_server { fs <name> }` for an `s3_proxy` block. Any `rewrite` that produced the path for `file_server` keeps producing the key. Check that the endpoint variable is set on the host and carries its scheme: a `caddy.fs` module may have fallen back to the SDK's environment lookup when `endpoint` was empty, while this one fails `caddy validate`. Afterwards, your bucket's metrics should show one read operation per cache miss or range slice, and no list operations at all.

## Out of scope

Writes, listing, directory indexes, presigned URLs, AWS credential chains and instance roles, retries, several buckets in one directive, caching of any kind. The last is a job for the module in front, and the rest would turn one request into several.

## Testing

```sh
go test -race ./...          # everything, including the Caddy integration test on ports 2999 and 9080
go test -short -race .       # unit tests only
```
