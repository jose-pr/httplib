"""Jar files: owner-only, replaced whole, LF, written only when something
changed, and no directory made before the first write."""

import os
import stat
import sys
import threading

import pytest

from syshttp.cookies import CookieSpec, save_netscape
from syshttp.env import HTTPEnv
from syshttp.jar import FileCookieJar, FileTokenJar, MemoryCookieJar, store_root
from test_cookies import _get, web  # noqa: F401  (fixture reused)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Windows has no POSIX mode bits")


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_files_are_owner_only_and_new_directories_private(tmp_path):
    old_umask = os.umask(0o022)
    try:
        root = tmp_path / "state" / "syshttp"
        FileTokenJar(root)["api.example"] = "secret"
        FileCookieJar(root)["api.example"] = [CookieSpec("api.example", "/", False, None, "sid", "v")]
    finally:
        os.umask(old_umask)
    for directory in (root, root / "tokens", root / "cookies"):
        assert _mode(directory) == 0o700, directory
    assert _mode(root / "tokens" / "api.example.token") == 0o600
    assert _mode(root / "cookies" / "api.example.txt") == 0o600


@posix_only
def test_an_existing_directory_keeps_its_mode(tmp_path):
    root = tmp_path / "shared"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    FileTokenJar(root)["h"] = "t"
    assert _mode(root) == 0o755
    assert _mode(root / "tokens") == 0o700


def test_the_files_are_written_with_lf(tmp_path):
    FileTokenJar(tmp_path)["h"] = "tok"
    save_netscape([CookieSpec("h", "/", False, None, "a", "1")], tmp_path / "jar.txt")
    assert (tmp_path / "tokens" / "h.token").read_bytes() == b"tok\n"
    assert b"\r" not in (tmp_path / "jar.txt").read_bytes()


def test_home_expands_a_tilde(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert store_root(env=HTTPEnv(environ={"SYSHTTP_HOME": "~/jars"})) == tmp_path / "jars"


def test_a_jar_makes_no_directory_until_it_writes(tmp_path):
    root = tmp_path / "state"
    tokens, cookies = FileTokenJar(root), FileCookieJar(root)
    assert not root.exists()
    assert tokens.get("h") is None and cookies.get("h") == []
    tokens["h"] = "t"
    assert (root / "tokens" / "h.token").exists() and not (root / "cookies").exists()


def test_a_reader_never_sees_a_half_written_token(tmp_path):
    jar = FileTokenJar(tmp_path)
    token = "tok" * 200
    jar["h"] = token
    stop = threading.Event()

    def rewrite():
        while not stop.is_set():
            jar["h"] = token

    writer = threading.Thread(target=rewrite)
    writer.start()
    try:
        seen = [jar.get("h") for _ in range(2000)]
    finally:
        stop.set()
        writer.join()
    assert [value for value in seen if value != token] == []


def test_a_failed_write_keeps_the_old_file_and_leaves_no_temporary(tmp_path, monkeypatch):
    jar = FileTokenJar(tmp_path)
    jar["h"] = "old"

    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        jar["h"] = "new"
    monkeypatch.undo()
    assert jar["h"] == "old"
    assert sorted(p.name for p in (tmp_path / "tokens").iterdir()) == ["h.token"]


class _CountingJar(MemoryCookieJar):
    writes = 0

    def __setitem__(self, key, value):
        type(self).writes += 1
        super().__setitem__(key, value)


def test_ten_responses_without_set_cookie_write_nothing(web):  # noqa: F811
    from syshttp.client import HTTPClient

    _CountingJar.writes = 0
    client = HTTPClient(cookies=_CountingJar(), retries=0, env=web)
    for _ in range(10):
        _get(client, "http://bank.test/")
    assert _CountingJar.writes == 0
    _get(client, "http://bank.test/", "k=1; Path=/")
    _get(client, "http://bank.test/")
    _get(client, "http://bank.test/")
    assert _CountingJar.writes == 1


def test_a_response_that_changes_nothing_writes_nothing_and_a_loaded_jar_is_not_rewritten(web):  # noqa: F811
    from syshttp.client import HTTPClient

    jar = _CountingJar({"bank.test": [CookieSpec(".bank.test", "/", False, None, "login", "1")]})
    _CountingJar.writes = 0
    client = HTTPClient(cookies=jar, retries=0, env=web)
    assert _get(client, "http://bank.test/") == "login=1"
    _get(client, "http://bank.test/", "login=1; Domain=bank.test; Path=/")
    assert _CountingJar.writes == 0, "the same row again is no change"
    _get(client, "http://bank.test/", "login=2; Domain=bank.test; Path=/")
    assert _CountingJar.writes == 1
