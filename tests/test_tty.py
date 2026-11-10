"""A pseudo terminal for the container: the container's process gets a terminal and the keys go to it."""
import os
import pty
import re
import select
import struct
import fcntl
import termios
import time

import pytest

from conftest import IMAGE, SRC, needs_docker

pytestmark = needs_docker


class Session:
    """A command running on a pseudo terminal of the test: send keys, read what it prints."""

    def __init__(self, argv, env=None, size=(24, 80)):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvpe(argv[0], argv, env or os.environ)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", size[0], size[1], 0, 0))
        self.buffer = ""

    def send(self, text):
        os.write(self.fd, text.encode())

    def read_until(self, pattern, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pattern, self.buffer):
                return self.buffer
            r, _, _ = select.select([self.fd], [], [], 0.2)
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    break
                if not data:
                    break
                self.buffer += data.decode("utf-8", "replace")
        raise AssertionError("never saw %r in %r" % (pattern, self.buffer))

    def finish(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            try:
                r, _, _ = select.select([self.fd], [], [], 0.2)
                if r:
                    self.buffer += os.read(self.fd, 65536).decode("utf-8", "replace")
            except OSError:
                pass
        raise AssertionError("it did not end: %r" % self.buffer)


@pytest.fixture
def env(root):
    return dict(os.environ, PYTHONPATH=SRC, KONTEYNER_ROOT=root, PYTHONDONTWRITEBYTECODE="1")


def start(env, *args, size=(24, 80)):
    import sys

    return Session([sys.executable, "-m", "kendi_konteyner", *args], env, size)


def test_the_process_has_a_terminal(env, image, docker):
    s = start(env, "run", "--rm", "-it", "--network", "none", "--hostname", "tty-box", IMAGE, "sh")
    s.read_until(r"#")
    s.send("tty; echo term=$TERM; test -t 0 && test -t 1 && test -t 2 && echo all-three-are-ttys; stty size; hostname; exit 5\n")
    out = s.read_until(r"tty-box")
    code = s.finish()
    assert code == 5
    assert "/dev/pts/0" in out and "term=xterm" in out and "all-three-are-ttys" in out and "24 80" in out
    # Docker answers the same
    d = Session(["docker", "run", "--rm", "-it", "--network", "none", "--hostname", "tty-box", IMAGE, "sh"], size=(24, 80))
    d.read_until(r"#")
    d.send("tty; echo term=$TERM; test -t 0 && test -t 1 && test -t 2 && echo all-three-are-ttys; stty size; hostname; exit 5\n")
    theirs = d.read_until(r"tty-box")
    d.finish()
    for line in ("/dev/pts/0", "term=xterm", "all-three-are-ttys", "24 80"):
        assert line in theirs


def test_without_a_terminal_there_is_none(kk, image):
    out = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "test -t 0 && echo tty0 || echo no-tty0; test -t 1 && echo tty1 || echo no-tty1")
    assert out.out.split() == ["no-tty0", "no-tty1"]


def test_ctrl_c_stops_the_foreground_process_and_not_the_container(env, image):
    s = start(env, "run", "--rm", "-it", "--network", "none", IMAGE, "sh")
    s.read_until(r"#")
    s.send("sleep 100\n")
    time.sleep(0.5)
    s.send("\x03")  # the terminal turns this into SIGINT for the foreground process group
    s.read_until(r"#")
    s.send("echo still-here; exit 0\n")
    s.read_until(r"still-here")
    assert s.finish() == 0


def test_keys_are_echoed_and_line_editing_works(env, image):
    s = start(env, "run", "--rm", "-it", "--network", "none", IMAGE, "sh", "-c", "echo ready; exec cat")
    s.read_until(r"ready")  # keys sent before the terminal is in raw mode would be thrown away with the line discipline's input
    time.sleep(0.3)
    s.send("hello\n")
    s.read_until(r"hello\r\nhello")  # the terminal echoes what is typed, cat prints it back
    s.send("\x04")  # end of file
    assert s.finish() == 0


def test_the_size_of_the_terminal_is_passed_on(env, image):
    s = start(env, "run", "--rm", "-it", "--network", "none", IMAGE, "sh", size=(40, 132))
    s.read_until(r"#")
    s.send("stty size; exit\n")
    s.read_until(r"40 132")
    s.finish()


def test_exec_with_a_terminal(env, kk, image):
    kk("run", "-d", "--name", "ttyexec", "--network", "none", IMAGE, "sleep", "60")
    s = start(env, "exec", "-it", "ttyexec", "sh")
    s.read_until(r"#")
    s.send("tty; ps | grep -c '[s]leep 60'; exit 4\n")
    assert "/dev/pts/" in s.read_until(r"/dev/pts/\d+\r\n1")
    assert s.finish() == 4


def test_standard_input_without_a_terminal(kk, image):
    out = kk("run", "--rm", "-i", "--network", "none", IMAGE, "sh", "-c", "read a; read b; echo got:$a,$b", input="one\ntwo\n")
    assert out.out == "got:one,two\n"
    out = kk("run", "--rm", "--network", "none", IMAGE, "cat", input="piped in\n")
    assert out.out == "piped in\n"
