# Changelog

## 1.0.0

First release.

* `s3_proxy`, an HTTP handler that fetches an object from an S3-compatible bucket with exactly one signed `GET` or `HEAD` per request and streams the body.
* Hand-rolled SigV4 signing, `Range` passed through and signed, no AWS SDK.
* The module reads nothing from the environment. Endpoint, bucket, region and credentials come from the configuration only, typically as `{$VAR}` placeholders substituted by the Caddyfile adapter.
* Response headers forwarded from an allowlist; `x-amz-*`, `cf-*`, `Server` and `Date` dropped. A header already set in front of the handler wins over the bucket's, as with `file_server`.
* A body that is cut short upstream aborts the connection, as `reverse_proxy` does, so that nothing in front stores a truncated response.
