"""Run on Windows: python -m unittest discover -s glazewm -p 'test_*.py'."""
import ctypes
import queue
import struct
import unittest
from unittest.mock import Mock, patch

import clipboard
import terminal_fast as fast


def unpack_string(data, offset=0):
    length, = struct.unpack_from('<I', data, offset)
    start = offset + 4
    end = start + length * 2
    return data[start:end].decode('utf-16-le'), end


class PayloadTests(unittest.TestCase):
    def test_utf16_code_units_including_terminator(self):
        data = fast.serialize_string('a\U0001f600')
        self.assertEqual(struct.unpack_from('<I', data)[0], 4)
        self.assertEqual(unpack_string(data), ('a\U0001f600\0', len(data)))

    def test_handoff_layout_and_quoted_home(self):
        home = 'C:\\Users\\a user'
        data = fast.handoff_payload(home, {'B': 'two', 'A': 'one'})
        command, offset = unpack_string(data)
        env, offset = unpack_string(data, offset)
        cwd, offset = unpack_string(data, offset)
        self.assertEqual(command, 'wt.exe -w new -d "C:\\Users\\a user"\0')
        self.assertEqual(env, 'A=one\0B=two\0\0')
        self.assertEqual(cwd, home + '\0')
        self.assertEqual(data[offset:], struct.pack('<I', 5))

    def test_engine_class_excludes_admin_preview_and_title_lookalikes(self):
        self.assertTrue(fast.ENGINE_CLASS.fullmatch('Windows Terminal 0123456789abcdef'))
        for value in ['Windows Terminal Admin 0123456789abcdef',
                      'Windows Terminal Preview 0123456789abcdef',
                      'Windows Terminal arbitrary title']:
            self.assertIsNone(fast.ENGINE_CLASS.fullmatch(value))


class LauncherTests(unittest.TestCase):
    def setUp(self):
        # Do not start the background worker in unit tests.
        self.launcher = fast.FastTerminalLauncher.__new__(fast.FastTerminalLauncher)
        self.launcher._engine = None
        self.launcher._requests = queue.Queue()

    def test_no_engine_leaves_key_to_glazewm(self):
        self.assertFalse(self.launcher.try_launch())
        self.assertTrue(self.launcher._requests.empty())

    def test_closed_engine_leaves_key_to_glazewm(self):
        self.launcher._engine = (123, 456)
        with patch.object(fast.user32, 'IsWindow', return_value=0):
            self.assertFalse(self.launcher.try_launch())
        self.assertTrue(self.launcher._requests.empty())

    def test_valid_engine_queues_without_doing_ipc_on_hook_thread(self):
        self.launcher._engine = (123, 456)
        with patch.object(fast.user32, 'IsWindow', return_value=1), \
             patch.object(fast.FastTerminalLauncher, '_send') as send:
            self.assertTrue(self.launcher.try_launch())
        send.assert_not_called()
        self.assertEqual(self.launcher._requests.get_nowait(), (123, 456))

    def test_reused_hwnd_does_not_receive_a_handoff(self):
        def different_pid(hwnd, ptr):
            ptr._obj.value = 789
        with patch.object(fast.user32, 'GetWindowThreadProcessId', side_effect=different_pid), \
             patch.object(fast.user32, 'SendMessageTimeoutW') as send:
            self.assertFalse(fast.FastTerminalLauncher._send((123, 456)))
        send.assert_not_called()


class HookTests(unittest.TestCase):
    def setUp(self):
        self.launcher = Mock()
        self.launcher.try_launch.return_value = True
        self.old_launcher = clipboard._terminal_launcher
        clipboard._terminal_launcher = self.launcher
        clipboard._terminal_enter_down = False
        self.chain = patch.object(clipboard.user32, 'CallNextHookEx', return_value=42)
        self.chain.start()
        self.down = patch.object(clipboard, '_down', return_value=False)
        self.down.start()

    def tearDown(self):
        self.down.stop()
        self.chain.stop()
        clipboard._terminal_launcher = self.old_launcher
        clipboard._terminal_enter_down = False

    def enter(self, message=0x104, flags=0x20):
        event = clipboard.KBDLLHOOKSTRUCT(0x0D, 0, flags, 0, 0)
        return clipboard._proc(0, message, ctypes.addressof(event))

    def test_alt_enter_intercepted_once_with_repeat_and_keyup_suppression(self):
        self.assertEqual(self.enter(), 1)
        self.assertEqual(self.enter(), 1)
        self.assertEqual(self.enter(0x105), 1)
        self.launcher.try_launch.assert_called_once()
        self.assertFalse(clipboard._terminal_enter_down)

    def test_cold_start_falls_through(self):
        self.launcher.try_launch.return_value = False
        self.assertEqual(self.enter(), 42)
        self.assertFalse(clipboard._terminal_enter_down)

    def test_plain_enter_is_not_intercepted(self):
        self.assertEqual(self.enter(0x100, flags=0), 42)
        self.launcher.try_launch.assert_not_called()

    def test_modified_alt_enter_is_not_intercepted(self):
        for modifier in [*clipboard.CTRL_VKS, 0xA0, 0xA1, 0x5B, 0x5C]:
            with self.subTest(modifier=modifier), patch.object(clipboard, '_down', side_effect=lambda vk: vk == modifier):
                self.assertEqual(self.enter(), 42)
        self.launcher.try_launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
