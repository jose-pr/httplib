# httplib

**HTTP plumbing that behaves the same in every client you build on it.**
`httplib` decides which proxy to use, with which credential and for which
hosts. It speaks to URL-prefix gateways, files cookies and tokens under the
origin's host, and verifies TLS through the operating system's trust store.
Those pieces use only the standard library. An optional `requests` session
(`pip install 'httplib[session]'`) applies all of them in one transport
adapter.

```python
from httplib.session import new_session

s = new_session(cookies=True, tokens=True)
print(s.get("https://example.com/").status_code)
```

- [Settings](settings.md): the variables, their prefix, and `HTTPEnv`.
- API reference: one page per module, in the navigation.
- [Changelog](changelog.md).

Source: <https://github.com/jose-pr/httplib>.
