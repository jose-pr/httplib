# syshttp

**HTTP plumbing that behaves the same in every client you build on it.**
`syshttp` decides which proxy to use, with which credential and for which
hosts. It speaks to URL-prefix gateways, files cookies and tokens under the
origin's host, and has the operating system verify certificates. With no
proxy variable set it routes the way the system does (its proxy settings, PAC,
WPAD). An optional `requests` session
(`pip install 'syshttp[session]'`) applies all of them in one transport
adapter.

```python
from syshttp.session import new_session

s = new_session(cookies=True, tokens=True)
print(s.get("https://example.com/").status_code)
```

- [Settings](settings.md): the variables, their prefix, and `HTTPEnv`.
- API reference: one page per module, in the navigation.
- [Changelog](changelog.md).

Source: <https://github.com/jose-pr/syshttp>.
