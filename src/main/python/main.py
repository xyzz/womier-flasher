from fbs_runtime.application_context.PyQt5 import ApplicationContext
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QProgressBar, QGroupBox, QComboBox, QSizePolicy, QToolButton

import sys
import hid
import struct
import time
import threading

RESPONSE_LEN = 65

CMD_BASE = 0x55AA00
CMD_INIT = CMD_BASE + 1

def hid_set_feature(dev, report):
    if len(report) > 64:
        raise RuntimeError("report must be less than 64 bytes")
    report += b"\x00" * (64 - len(report))

    dev.send_feature_report(report)

def hid_get_feature(dev):
    return dev.get_feature_report(0, RESPONSE_LEN)

def console_progress(msg, progress):
    print("{}: {:.2f}%".format(msg, 100 * progress))

def console_error(msg):
    print("Error: {}".format(msg))

def cmd_flash(dev, progress_cb=console_progress, error_cb=console_error):
    # 1) Initialize
    progress_cb("Initialize", 0)
    hid_set_feature(dev, struct.pack("<I", CMD_INIT))
    resp = bytes(hid_get_feature(dev))
    if len(resp) != RESPONSE_LEN:
        return error_cb("Failed to initialize: got response of length {} expected {}".format(len(resp), RESPONSE_LEN))
    resp = resp[1:]
    cmd, status = struct.unpack("<II", resp[0:8])
    if cmd != CMD_INIT:
        return error_cb("failed to initialize, response 0x{:08X} expected 0x{:08X}".format(cmd, CMD_INIT))
    progress_cb("Initialize", 1)

    # 2) Prepare for flash
    for x in range(100):
        progress_cb("test", x / 100)
        time.sleep(0.05)

    progress_cb("Finished", 1)

    error_cb("test error")

class CustomProgressBar(QProgressBar):
    def __init__(self):
        super().__init__()
        self._text = None

    def setText(self, text):
        self._text = text

    def text(self):
        return self._text

class MainWindow(QWidget):

    progress_signal = pyqtSignal(object)
    error_signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()

        self.progress_signal.connect(self._on_progress)
        self.error_signal.connect(self._on_error)

        btn_flash_qmk = QPushButton("Flash QMK...")
        btn_flash_qmk.clicked.connect(self.do_flash)

        lbl_help = QLabel("After jumploader is installed, hold Backspace while plugging in the keyboard to start in bootloader mode.")
        lbl_help.setWordWrap(True)

        btn_reboot_bl = QPushButton("Reboot to Bootloader")
        btn_flash_jumploader = QPushButton("Flash Jumploader")
        btn_restore_stock = QPushButton("Revert to Stock Firmware")

        self.progress = CustomProgressBar()
        self.progress.setRange(0, 100)

        combobox = QComboBox()
        btn_refresh_devices = QToolButton()
        btn_refresh_devices.setToolButtonStyle(Qt.ToolButtonTextOnly)
        btn_refresh_devices.setText("Refresh")

        devices_layout = QHBoxLayout()
        devices_layout.addWidget(combobox)
        devices_layout.addWidget(btn_refresh_devices)

        layout_qmk = QVBoxLayout()
        layout_qmk.setAlignment(Qt.AlignTop)
        layout_qmk.addWidget(btn_flash_qmk)
        layout_qmk.addWidget(lbl_help)

        layout_stock = QVBoxLayout()
        layout_stock.setAlignment(Qt.AlignTop)
        layout_stock.addWidget(btn_reboot_bl)
        layout_stock.addWidget(btn_flash_jumploader)
        layout_stock.addWidget(btn_restore_stock)

        group_qmk = QGroupBox("QMK")
        group_qmk.setLayout(layout_qmk)

        group_stock = QGroupBox("Stock")
        group_stock.setLayout(layout_stock)

        group_layout = QHBoxLayout()
        group_layout.addWidget(group_qmk)
        group_layout.addWidget(group_stock)

        layout = QVBoxLayout()
        layout.addLayout(devices_layout)
        layout.addLayout(group_layout)
        layout.addWidget(self.progress)
        self.setLayout(layout)

    def _on_progress(self, args):
        msg, progress = args
        progress = int(progress * 100)
        self.progress.setText("{}: {}%".format(msg, progress))
        self.progress.setValue(progress)

    def _on_error(self, args):
        msg = args
        print("error", msg)

    def on_progress(self, msg, progress):
        self.progress_signal.emit([msg, progress])

    def on_error(self, msg):
        self.error_signal.emit(msg)

    def do_flash(self):
        print("flashing")
        dev = hid.device()
        dev.open(0x0c45, 0x7010)

        t = threading.Thread(target=lambda: cmd_flash(dev, self.on_progress, self.on_error))
        t.start()


if __name__ == '__main__':
    appctxt = ApplicationContext()
    window = MainWindow()
    window.resize(600, 250)
    window.setWindowTitle("Womier Bricker")
    window.show()
    exit_code = appctxt.app.exec_()
    sys.exit(exit_code)