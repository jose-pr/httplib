# `syshttp.client`

A synchronous HTTP client on the standard library. `syshttp.fetch` is
`syshttp.client.fetch`.

`HTTPClient(transport=...)` sends through any object with `send()` and
`close()` (the `Transport` protocol), such as a transport built on `requests`
or `httpx`, or a fake in a test. The client owns redirects, credentials,
cookies, tokens, hooks, retries and the deadline; the transport owns routing,
TLS verification, connection reuse and content decoding. A transport written
elsewhere therefore handles proxies and TLS itself, as its library does;
`prepare_request()` gives it the checks and body framing of syshttp's own, and
`SYSHTTP_DEFAULT_TRANSPORT` makes it the default (see [Settings](../settings.md)).

::: syshttp.client
