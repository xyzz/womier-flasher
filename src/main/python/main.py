from fbs_runtime.application_context.PyQt5 import ApplicationContext
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QProgressBar, QGroupBox, \
    QComboBox, QSizePolicy, QToolButton, QMessageBox, QFileDialog

import sys
import hid
import struct
import time
import threading
import traceback

# TODO: dry-run support to ensure flashing doesn't crash

RESPONSE_LEN = 64
MAX_FIRMWARE = 0x7800
QMK_OFFSET = 0x200
QMK_MAX_FIRMWARE = MAX_FIRMWARE - 0x200  # 0x200 for the jumploader

CMD_BASE = 0x55AA00
CMD_INIT = CMD_BASE + 1
CMD_PREPARE = CMD_BASE + 5
CMD_REBOOT = CMD_BASE + 7

EXPECTED_STATUS = 0xFAFAFAFA

DEVICE_DESC = {
    (1, 2): "Womier K66",  # TODO
    (0x0c45, 0x7010): "Womier K66 (bootloader)"
}

def hid_set_feature(dev, report):
    if len(report) > 64:
        raise RuntimeError("report must be less than 64 bytes")
    report += b"\x00" * (64 - len(report))

    # add 00 at start for hidapi report id
    dev.send_feature_report(b"\x00" + report)

def hid_get_feature(dev):
    # strip 00 at start for hidapi report id
    return dev.get_feature_report(0, RESPONSE_LEN + 1)[1:]

def console_progress(msg, progress):
    print("{}: {:.2f}%".format(msg, 100 * progress))

def console_complete():
    pass

def console_error(msg):
    print("Error: {}".format(msg))

def cmd_flash(dev, offset, firmware, progress_cb=console_progress, complete_cb=console_complete, error_cb=console_error):
    while len(firmware) % 64 != 0:
        firmware += b"\x00"

    if len(firmware) + offset > MAX_FIRMWARE:
        return error_cb("Firmware is too large to flash")

    # 1) Initialize
    progress_cb("Initialize", 0)
    hid_set_feature(dev, struct.pack("<I", CMD_INIT))
    resp = bytes(hid_get_feature(dev))
    if len(resp) != RESPONSE_LEN:
        return error_cb("Failed to initialize: got response of length {}, expected {}".format(len(resp), RESPONSE_LEN))
    cmd, status = struct.unpack("<II", resp[0:8])
    if cmd != CMD_INIT:
        return error_cb("Failed to initialize: response cmd is 0x{:08X}, expected 0x{:08X}".format(cmd, CMD_INIT))
    progress_cb("Initialize", 1)

    # 2) Prepare for flash
    hid_set_feature(dev, struct.pack("<III", CMD_BASE + 5, offset, len(firmware) // 64))
    resp = bytes(hid_get_feature(dev))
    if len(resp) != RESPONSE_LEN:
        return error_cb("Failed to prepare: got response of length {}, expected {}".format(len(resp), RESPONSE_LEN))
    cmd, status = struct.unpack("<II", resp[0:8])
    if cmd != CMD_PREPARE:
        return error_cb("Failed to prepare: response cmd is 0x{:08X}, expected 0x{:08X}".format(cmd, CMD_PREPARE))
    if status != EXPECTED_STATUS:
        return error_cb("Failed to prepare: response status is 0x{:08X}, expected 0x{:08X}".format(status, EXPECTED_STATUS))
    progress_cb("Prepare", 1)

    # 3) Flash
    progress_cb("Flash", 0)
    for addr in range(0, len(firmware), 64):
        chunk = firmware[addr:addr+64]
        hid_set_feature(dev, chunk)

        progress_cb("Flash", (addr + 64) / len(firmware))

    # 4) Reboot
    hid_set_feature(dev, struct.pack("<I", CMD_REBOOT))
    complete_cb()

class MainWindow(QWidget):

    progress_signal = pyqtSignal(object)
    complete_signal = pyqtSignal(object)
    error_signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()

        self.dev = None

        self.progress_signal.connect(self._on_progress)
        self.complete_signal.connect(self._on_complete)
        self.error_signal.connect(self._on_error)

        btn_flash_qmk = QPushButton("Flash QMK...")
        btn_flash_qmk.clicked.connect(self.on_click_flash_qmk)

        lbl_help = QLabel("After jumploader is installed, hold Backspace while plugging in the keyboard to start in bootloader mode.")
        lbl_help.setWordWrap(True)

        btn_reboot_bl = QPushButton("Reboot to Bootloader")
        btn_flash_jumploader = QPushButton("Flash Jumploader")
        btn_restore_stock = QPushButton("Revert to Stock Firmware")

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress_label = QLabel("Ready")

        self.combobox_devices = QComboBox()
        btn_refresh_devices = QToolButton()
        btn_refresh_devices.setToolButtonStyle(Qt.ToolButtonTextOnly)
        btn_refresh_devices.setText("Refresh")
        btn_refresh_devices.clicked.connect(self.on_click_refresh)

        devices_layout = QHBoxLayout()
        devices_layout.addWidget(self.combobox_devices)
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

        layout_progress = QVBoxLayout()
        layout_progress.addWidget(self.progress_label)
        layout_progress.addWidget(self.progress)

        group_qmk = QGroupBox("QMK")
        group_qmk.setLayout(layout_qmk)

        group_stock = QGroupBox("Stock")
        group_stock.setLayout(layout_stock)

        group_progress = QGroupBox("")
        group_progress.setLayout(layout_progress)

        group_layout = QHBoxLayout()
        group_layout.addWidget(group_qmk)
        group_layout.addWidget(group_stock)

        layout = QVBoxLayout()
        layout.addLayout(devices_layout, stretch=0)
        layout.addLayout(group_layout, stretch=1)
        layout.addWidget(group_progress, stretch=0)
        self.setLayout(layout)

        self.on_click_refresh()

    def lock_user(self):
        pass

    def unlock_user(self):
        self.close_dev()

    def close_dev(self):
        if self.dev is not None:
            self.dev.close()
            self.dev = None

    def _on_progress(self, args):
        msg, progress = args
        progress = int(progress * 100)
        self.progress.setValue(progress)
        self.progress_label.setText(msg)

    def _on_complete(self, args):
        self.progress_label.setText("Finished")
        self.unlock_user()

    def _on_error(self, msg):
        QMessageBox.critical(window, "Error", msg)
        self.unlock_user()

    def on_progress(self, msg, progress):
        self.progress_signal.emit([msg, progress])

    def on_complete(self):
        self.complete_signal.emit(None)

    def on_error(self, msg):
        self.error_signal.emit(msg)

    def on_click_refresh(self):
        self.devices = []
        self.combobox_devices.clear()

        for dev in hid.enumerate():
            vid, pid = dev["vendor_id"], dev["product_id"]
            if (vid, pid) in DEVICE_DESC:
                self.combobox_devices.addItem("{} [{:04X}:{:04X}]".format(DEVICE_DESC[(vid, pid)], vid, pid))
                self.devices.append(dev)

    def get_active_device(self):
        idx = self.combobox_devices.currentIndex()
        if idx == -1:
            self._on_error("No device selected")
            return None

        try:
            dev = hid.device()
            dev.open_path(self.devices[idx]["path"])
            return dev
        except OSError:
            self._on_error("Failed to open the device. You might not have sufficient permissions.")
            return None

    def sanity_check_qmk_firmware(self, firmware):
        # check the size so we don't trash bootloader
        # (ok, we wouldn't overwrite it anyway as it's checked again in cmd_flash)
        if len(firmware) > QMK_MAX_FIRMWARE:
            self._on_error("Firmware is too large: 0x{:X} max allowed is 0x{:X}".format(len(firmware), QMK_MAX_FIRMWARE))
            return False
        if len(firmware) < 0x100:
            self._on_error("Firmware is too small")
            return False
        firmware_valid = True
        # check stack pointer is valid and that first 3 vectors have bit0 set
        sp, *vecs = struct.unpack("<IIII", firmware[0:16])
        if sp < 0x20000000 or sp > 0x20000800 or vecs[0] & 1 != 1 or vecs[1] & 1 != 1 or vecs[2] & 1 != 1:
            self._on_error("Firmware appears to be corrupted")
            return False
        return True

    def on_click_flash_qmk(self):
        self.dev = self.get_active_device()
        if not self.dev:
            return

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename = QFileDialog.getOpenFileName(None, "Select firmware to flash", "", "Firmware Files (*.bin)", options=options)[0]
        if not filename:
            self.close_dev()
            return

        with open(filename, "rb") as inf:
            firmware = inf.read()

        if not self.sanity_check_qmk_firmware(firmware):
            self.close_dev()
            return

        threading.Thread(target=lambda: cmd_flash(self.dev, QMK_OFFSET, firmware, self.on_progress, self.on_complete, self.on_error)).start()


def excepthook(exc_type, exc_value, exc_tb):
    exc = traceback.format_exception(exc_type, exc_value, exc_tb)
    QMessageBox.critical(window, "Fatal error", "".join(exc))
    sys.exit(1)


if __name__ == '__main__':
    appctxt = ApplicationContext()
    window = MainWindow()
    window.resize(600, 250)
    window.setWindowTitle("Womier Bricker")
    window.show()
    sys.excepthook = excepthook
    exit_code = appctxt.app.exec_()
    sys.exit(exit_code)
