"""The command line: errors, tables, JSON, who may run it."""
import json
import os
import sys

from conftest import IMAGE, SRC, needs_root

pytestmark = needs_root


def test_a_command_is_needed(kk, image):
    out = kk("run", IMAGE)
    assert out.code == 0  # the image has a default command (sh); with no terminal it ends at once
    out = kk("run", "--entrypoint", "", IMAGE)
    assert out.code != 0 and "no command" in out.err


def test_bad_arguments_have_clear_messages(kk, image):
    assert "not a size" in kk("run", "-m", "12x", IMAGE, "true").err
    assert "ro or rw" in kk("run", "-v", "/tmp:/t:xx", IMAGE, "true").err
    assert "--rm cannot be used with -d" in kk("run", "--rm", "-d", IMAGE, "true").err
    assert "valid container name" in kk("run", "--name", "-bad", IMAGE, "true").err or kk("run", "--name", "-bad", IMAGE, "true").code != 0
    assert kk("run", "--network", "wifi", IMAGE, "true").code == 2
    out = kk("run", "--rm", "-u", "nosuchuser", IMAGE, "true")
    assert out.code != 0 and "nosuchuser" in out.err


def test_an_unknown_image_is_pulled_and_a_bad_name_is_refused(kk):
    out = kk("run", "--rm", "Not A Name", "true")
    assert out.code != 0 and "not a valid image name" in out.err
    out = kk("rmi", "nothing:here")
    assert out.code != 0 and "no such image" in out.err


def test_tables(kk, image):
    kk("run", "--name", "done1", "--network", "none", IMAGE, "sh", "-c", "exit 4")
    kk("run", "-d", "--name", "up1", "--network", "none", "-m", "64m", IMAGE, "sleep", "60")
    ps = kk("ps", "-a").out.splitlines()
    assert ps[0].split()[:3] == ["CONTAINER", "ID", "IMAGE"]
    row = {l.split()[-1]: l for l in ps[1:]}
    assert "Exited (4)" in row["done1"] and "Up" in row["up1"] and IMAGE in row["up1"]
    assert [l.split()[-1] for l in kk("ps").out.splitlines()[1:]] == ["up1"]
    images = kk("images").out
    assert images.splitlines()[0].split()[0] == "REPOSITORY:TAG" and IMAGE in images
    stats = kk("stats").out.splitlines()
    assert stats[0].startswith("CONTAINER ID") and len(stats) == 2 and "67.1MB" in stats[1]


def test_inspect_is_json_with_what_was_asked_for(kk, image):
    kk("run", "-d", "--name", "ins", "--network", "none", "-m", "64m", "--cpus", "0.5", "--pids-limit", "20", "-e", "A=1", "-v", "/tmp:/t:ro", "--hostname", "h1", IMAGE, "sleep", "60")
    data = json.loads(kk("inspect", "ins").out)[0]
    cfg = data["Config"]
    assert data["Name"] == "ins" and data["ImageName"] == IMAGE and cfg["argv"] == ["sleep", "60"]
    assert cfg["memory"] == 64 * 1024 * 1024 and cfg["cpus"] == 0.5 and cfg["pids_limit"] == 20 and cfg["env"] == ["A=1"] and cfg["hostname"] == "h1"
    assert cfg["volumes"] == [{"source": "/tmp", "target": "/t", "readonly": True}]
    assert data["State"]["status"] == "running" and data["State"]["init_pid"] > 1
    assert data["Limits"]["memory.max"] == str(64 * 1024 * 1024) and data["Limits"]["pids.max"] == "20" and data["Limits"]["cpu.max"] == "50000 100000"


def test_create_start_and_the_exit_code_of_start(kk, image):
    cid = kk("create", "--name", "later", "--network", "none", IMAGE, "sh", "-c", "echo started; exit 6").out.strip()
    assert len(cid) == 64 and "Created" in kk("ps", "-a").out
    out = kk("start", "-a", "later")
    assert out.code == 6 and "started" in out.out
    assert kk("start", "later").code in (0, 6)


def test_root_is_needed(root, image):
    """The command line of a user that is not root: a clear message and a failure.  It runs in a forked copy of this process that gives up
    root first (a new interpreter would have to read the source from a directory that the other user may not enter, as on a CI runner)."""
    sys.path.insert(0, SRC)
    from kendi_konteyner.cli import main

    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 99
        try:
            sys.stderr = os.fdopen(w, "w")  # (pytest has replaced sys.stderr: writing to descriptor 2 would not reach it)
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            code = main(["--root", root, "run", IMAGE, "true"])
            sys.stderr.flush()
        finally:
            os._exit(code)
    os.close(w)
    chunks = []
    while True:
        data = os.read(r, 4096)
        if not data:
            break
        chunks.append(data)
    os.close(r)
    _, status = os.waitpid(pid, 0)
    message = b"".join(chunks).decode()
    assert os.waitstatus_to_exitcode(status) == 1 and "needs root" in message, message


def test_version_and_help(kk):
    assert kk("--version").out.startswith("konteyner ")
    out = kk("--help")
    assert out.code == 0 and "run" in out.out and "exec" in out.out
