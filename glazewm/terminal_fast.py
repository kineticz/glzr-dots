"""Fast warm Windows Terminal launch for clipboard.py's Alt+Enter hook.

WT 1.24's wt.exe starts another process merely to forward its command line to
an existing Terminal engine. Send the same WM_COPYDATA handoff directly from
the already-resident keyboard helper instead (~160ms vs ~330ms on this PC).
This is a private WT protocol; only use it for the known 1.24 implementation.
Other versions, no running Terminal, or an inaccessible engine fall back to
GlazeWM's ordinary Alt+Enter binding. No prestarted shells or hidden windows.

Protocol source (serializeHandoffPayload / TERMINAL_HANDOFF_MAGIC):
https://github.com/microsoft/terminal/blob/v1.24.12741.0/src/cascadia/WindowsTerminal/WindowEmperor.cpp

All discovery, version checks and synchronous IPC run on a worker thread,
never inside the low-level keyboard hook. No command output or environment
contents are logged.
"""
import ctypes
from ctypes import wintypes
import logging
import os
from pathlib import Path
import queue
import re
import struct
import subprocess
import threading

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
version = ctypes.WinDLL('version', use_last_error=True)
HANDLE = wintypes.HANDLE
ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = [ENUMPROC, wintypes.LPARAM]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.IsWindow.argtypes = [wintypes.HWND]
user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
]
user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
user32.AllowSetForegroundWindow.argtypes = [wintypes.DWORD]
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [
    HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
]
kernel32.CloseHandle.argtypes = [HANDLE]
version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
version.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]

# Normal stable WT only, not Preview/Canary or elevated engines. Match the
# instance-class hash rather than a user-controlled window title.
ENGINE_CLASS = re.compile(r'Windows Terminal [0-9a-f]{16}(?: [0-9a-f]{16})?\Z')
HANDOFF_MAGIC = 0x4C414E494D524554 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x4D524554


class CopyData(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_size_t), ('size', wintypes.DWORD), ('data', ctypes.c_void_p)]


def serialize_string(text):
    """WT counts UTF-16 code units (including NUL), not Python characters."""
    data = (text + '\0').encode('utf-16-le', errors='surrogatepass')
    return struct.pack('<I', len(data) // 2) + data


def handoff_payload(home, environment):
    command = subprocess.list2cmdline(['wt.exe', '-w', 'new', '-d', home])
    # The serializer contributes the second NUL terminating the environment.
    env = '\0'.join(f'{key}={value}' for key, value in sorted(environment.items())) + '\0'
    return (serialize_string(command) + serialize_string(env) +
            serialize_string(home) + struct.pack('<I', 5))  # SW_SHOW


def _supported_executable(pid):
    process = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not process:
        return False
    try:
        path = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(path))
        if not kernel32.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(size)):
            return False
    finally:
        kernel32.CloseHandle(process)
    if Path(path.value).name.lower() != 'windowsterminal.exe':
        return False
    ignored = wintypes.DWORD()
    size = version.GetFileVersionInfoSizeW(path.value, ctypes.byref(ignored))
    if not size:
        return False
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path.value, 0, size, data):
        return False
    fixed = ctypes.c_void_p()
    length = wintypes.UINT()
    if not version.VerQueryValueW(data, '\\', ctypes.byref(fixed), ctypes.byref(length)):
        return False
    if length.value < 16:
        return False
    # VS_FIXEDFILEINFO: signature, struct version, file version MS, LS, ...
    fields = ctypes.cast(fixed, ctypes.POINTER(wintypes.DWORD))
    return fields[0] == 0xFEEF04BD and fields[2] == (1 << 16 | 24)


def find_engine():
    found = []

    @ENUMPROC
    def visit(hwnd, _):
        name = ctypes.create_unicode_buffer(128)
        user32.GetClassNameW(hwnd, name, len(name))
        if ENGINE_CLASS.fullmatch(name.value):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if _supported_executable(pid.value):
                found.append((hwnd, pid.value))
                return False
        return True

    user32.EnumWindows(visit, 0)
    return found[0] if found else None


class FastTerminalLauncher:
    def __init__(self):
        self._engine = None
        self._requests = queue.Queue()
        self._logger = logging.getLogger('glzr.terminal_fast')
        threading.Thread(target=self._run, name='terminal-launch', daemon=True).start()

    def try_launch(self):
        """Hook-safe: return False to let GlazeWM handle a cold start."""
        engine = self._engine
        if not engine or not user32.IsWindow(engine[0]):
            return False
        self._requests.put(engine)
        return True

    @staticmethod
    def _send(engine):
        hwnd, pid = engine
        # Revalidate the handle, executable and protocol after queueing: a
        # closed engine's HWND could have been reused by another application.
        actual_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(actual_pid))
        if actual_pid.value != pid or not _supported_executable(pid):
            return False
        home = os.path.expanduser('~')
        data = handoff_payload(home, os.environ)
        buffer = ctypes.create_string_buffer(data)
        message = CopyData(HANDOFF_MAGIC, len(data), ctypes.cast(buffer, ctypes.c_void_p))
        result = ctypes.c_size_t()
        user32.AllowSetForegroundWindow(pid)
        delivered = user32.SendMessageTimeoutW(
            hwnd, 0x4A, 0, ctypes.addressof(message), 0x22, 1000, ctypes.byref(result),
        )
        if not delivered:
            # Never retry after a timeout: the receiver might still execute
            # the request, in which case retrying would create two windows.
            raise ctypes.WinError(ctypes.get_last_error())
        return True

    @staticmethod
    def _fallback():
        subprocess.Popen(
            ['wt.exe', '-w', 'new', '-d', os.path.expanduser('~')],
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

    def _run(self):
        while True:
            try:
                self._engine = find_engine()
                try:
                    engine = self._requests.get(timeout=2)
                except queue.Empty:
                    continue
                if not self._send(engine):
                    self._fallback()
            except Exception:
                self._engine = None
                # Configure a file only on failure; no startup file I/O in
                # the keyboard hook and no accumulating success/timing log.
                if not self._logger.handlers:
                    try:
                        directory = Path(os.environ['LOCALAPPDATA']) / 'glazewm'
                        directory.mkdir(parents=True, exist_ok=True)
                        self._logger.addHandler(logging.FileHandler(directory / 'terminal-fast.log'))
                    except OSError:
                        pass
                self._logger.exception('Fast Terminal launch failed; disabling fast path until next discovery')
