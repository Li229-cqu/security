# -*- coding: utf-8 -*-
import sys
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
                             QGroupBox, QSplitter, QMessageBox, QFormLayout, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIntValidator

from sdes import (
    bits10_from_str, int_from_bits,
    encrypt_block8, decrypt_block8, encrypt_bytes, decrypt_bytes,
    brute_force_known_pairs, bits_from_int
)


class BruteForceThread(QThread):
    result_ready = pyqtSignal(list, float)

    def __init__(self, pairs):
        super().__init__()
        self.pairs = pairs

    def run(self):
        t0 = time.time()
        keys = brute_force_known_pairs(self.pairs)
        dt = time.time() - t0
        self.result_ready.emit(keys, dt)


class SDESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # 设置窗口基本属性
        self.setWindowTitle("S-DES 加密工具")
        self.setGeometry(100, 100, 900, 600)
        self.setMinimumSize(800, 500)

        # 创建主部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页控件
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 创建各个标签页
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_bruteforce_tab()

        # 设置字体
        font = QFont("SimHei", 10)
        self.setFont(font)

    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 输入区域
        input_group = QGroupBox("输入信息")
        input_layout = QFormLayout()

        # 密钥输入
        self.encrypt_key = QLineEdit()
        self.encrypt_key.setPlaceholderText("请输入10位二进制密钥")
        self.encrypt_key.setText("1010000010")
        input_layout.addRow("密钥:", self.encrypt_key)

        # 各种输入方式
        self.encrypt_ascii = QLineEdit()
        self.encrypt_ascii.setPlaceholderText("请输入ASCII文本")
        input_layout.addRow("ASCII文本:", self.encrypt_ascii)

        self.encrypt_bits = QLineEdit()
        self.encrypt_bits.setPlaceholderText("请输入8位二进制（可多块，空格分隔）")
        input_layout.addRow("二进制:", self.encrypt_bits)

        self.encrypt_hex = QLineEdit()
        self.encrypt_hex.setPlaceholderText("请输入十六进制")
        input_layout.addRow("十六进制:", self.encrypt_hex)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("执行加密")
        self.encrypt_btn.clicked.connect(self.do_encrypt)
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("加密结果")
        output_layout = QFormLayout()

        self.encrypt_out_hex = QLineEdit()
        self.encrypt_out_hex.setReadOnly(True)
        output_layout.addRow("十六进制结果:", self.encrypt_out_hex)

        self.encrypt_out_bits = QLineEdit()
        self.encrypt_out_bits.setReadOnly(True)
        output_layout.addRow("二进制结果:", self.encrypt_out_bits)

        self.encrypt_out_text = QLineEdit()
        self.encrypt_out_text.setReadOnly(True)
        output_layout.addRow("文本结果:", self.encrypt_out_text)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch()
        self.tabs.addTab(tab, "加密")

    def create_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 输入区域
        input_group = QGroupBox("输入信息")
        input_layout = QFormLayout()

        # 密钥输入
        self.decrypt_key = QLineEdit()
        self.decrypt_key.setPlaceholderText("请输入10位二进制密钥")
        self.decrypt_key.setText("1010000010")
        input_layout.addRow("密钥:", self.decrypt_key)

        # 各种输入方式
        self.decrypt_ascii = QLineEdit()
        self.decrypt_ascii.setPlaceholderText("请输入加密后的ASCII文本")
        input_layout.addRow("加密文本:", self.decrypt_ascii)

        self.decrypt_bits = QLineEdit()
        self.decrypt_bits.setPlaceholderText("请输入8位二进制密文（可多块，空格分隔）")
        input_layout.addRow("二进制密文:", self.decrypt_bits)

        self.decrypt_hex = QLineEdit()
        self.decrypt_hex.setPlaceholderText("请输入十六进制密文")
        input_layout.addRow("十六进制密文:", self.decrypt_hex)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.decrypt_btn = QPushButton("执行解密")
        self.decrypt_btn.clicked.connect(self.do_decrypt)
        btn_layout.addWidget(self.decrypt_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("解密结果")
        output_layout = QFormLayout()

        self.decrypt_out_hex = QLineEdit()
        self.decrypt_out_hex.setReadOnly(True)
        output_layout.addRow("十六进制结果:", self.decrypt_out_hex)

        self.decrypt_out_bits = QLineEdit()
        self.decrypt_out_bits.setReadOnly(True)
        output_layout.addRow("二进制结果:", self.decrypt_out_bits)

        self.decrypt_out_text = QLineEdit()
        self.decrypt_out_text.setReadOnly(True)
        output_layout.addRow("文本结果:", self.decrypt_out_text)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch()
        self.tabs.addTab(tab, "解密")

    def create_bruteforce_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 创建分割器
        splitter = QSplitter(Qt.Vertical)

        # 输入区域
        input_group = QGroupBox("明密文对（每行一个）")
        input_layout = QVBoxLayout()

        self.bf_pairs = QTextEdit()
        self.bf_pairs.setPlaceholderText("示例:\n01010101:11001100\n或\na5:3f")
        self.bf_pairs.setText("01010101:11001100")
        input_layout.addWidget(self.bf_pairs)

        # 说明文本
        info_label = QLabel(
            "格式说明:\n- 二进制: 8位:8位 (如 01010101:11001100)\n- 十六进制: 2位:2位 (如 a5:3f)\n可混合输入多种格式")
        info_label.setStyleSheet("color: #666; font-size: 9pt;")
        input_layout.addWidget(info_label)

        input_group.setLayout(input_layout)
        splitter.addWidget(input_group)

        # 结果区域
        result_group = QGroupBox("暴力破解结果")
        result_layout = QVBoxLayout()

        self.bf_result = QTextEdit()
        self.bf_result.setReadOnly(True)
        result_layout.addWidget(self.bf_result)

        result_group.setLayout(result_layout)
        splitter.addWidget(result_group)

        # 设置分割器比例
        splitter.setSizes([200, 300])

        layout.addWidget(splitter)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.bf_btn = QPushButton("开始暴力破解")
        self.bf_btn.clicked.connect(self.start_bruteforce)
        btn_layout.addWidget(self.bf_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.tabs.addTab(tab, "暴力破解")

    def parse_bits_blocks(self, bits_str):
        s = bits_str.strip()
        if not s:
            raise ValueError("Bits输入为空")
        if any(ch not in "01 " for ch in s):
            raise ValueError("Bits只能包含0/1与空格")
        groups = s.split()
        for g in groups:
            if len(g) != 8 or any(c not in "01" for c in g):
                raise ValueError(f"每块必须是8位二进制：{g}")
        return groups

    def do_encrypt(self):
        try:
            key = bits10_from_str(self.encrypt_key.text())
        except Exception as e:
            QMessageBox.critical(self, "密钥错误", str(e))
            return

        text = self.encrypt_ascii.text()
        bits = self.encrypt_bits.text().strip()
        hx = self.encrypt_hex.text().strip()

        try:
            if text:
                out = encrypt_bytes(text.encode('latin-1', errors='ignore'), key)
            elif bits:
                groups = self.parse_bits_blocks(bits)
                out = bytearray()
                for g in groups:
                    pbits = [int(c) for c in g]
                    cbits = encrypt_block8(pbits, key)
                    out.append(int_from_bits(cbits))
                out = bytes(out)
            elif hx:
                data = bytes.fromhex(hx)
                out = encrypt_bytes(data, key)
            else:
                QMessageBox.information(self, "输入缺失", "请在ASCII/Bits/Hex中任选一种输入")
                return

            self.encrypt_out_hex.setText(out.hex())
            self.encrypt_out_bits.setText(" ".join(format(x, "08b") for x in out))
            self.encrypt_out_text.setText("（密文包含不可见字符，未直接显示）")
        except Exception as e:
            QMessageBox.critical(self, "加密出错", str(e))

    def do_decrypt(self):
        try:
            key = bits10_from_str(self.decrypt_key.text())
        except Exception as e:
            QMessageBox.critical(self, "密钥错误", str(e))
            return

        text = self.decrypt_ascii.text()
        bits = self.decrypt_bits.text().strip()
        hx = self.decrypt_hex.text().strip()

        try:
            if text:
                data = text.encode('latin-1', errors='ignore')
                out = decrypt_bytes(data, key)
            elif bits:
                groups = self.parse_bits_blocks(bits)
                out = bytearray()
                for g in groups:
                    cbits = [int(c) for c in g]
                    pbits = decrypt_block8(cbits, key)
                    out.append(int_from_bits(pbits))
                out = bytes(out)
            elif hx:
                data = bytes.fromhex(hx)
                out = decrypt_bytes(data, key)
            else:
                QMessageBox.information(self, "输入缺失", "请在ASCII/Bits/Hex中任选一种输入")
                return

            self.decrypt_out_hex.setText(out.hex())
            self.decrypt_out_bits.setText(" ".join(format(x, "08b") for x in out))
            try:
                self.decrypt_out_text.setText(out.decode('latin-1'))
            except UnicodeDecodeError:
                self.decrypt_out_text.setText("（解密结果包含不可见字符）")
        except Exception as e:
            QMessageBox.critical(self, "解密出错", str(e))

    def parse_pair_text(self, raw):
        pairs = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise ValueError(f"缺少冒号：{line}")
            p, c = [x.strip() for x in line.split(":", 1)]

            def to_byte(x):
                x2 = x.replace(" ", "").lower()
                if set(x2) <= {"0", "1"} and len(x2) == 8:
                    return int(x2, 2)
                if all(ch in "0123456789abcdef" for ch in x2) and len(x2) == 2:
                    return int(x2, 16)
                raise ValueError(f"格式错误（需8位二进制或2位十六进制）：{x}")

            pairs.append((to_byte(p), to_byte(c)))

        if not pairs:
            raise ValueError("未输入任何明密文对")
        return pairs

    def start_bruteforce(self):
        try:
            pairs = self.parse_pair_text(self.bf_pairs.toPlainText())
        except Exception as e:
            QMessageBox.critical(self, "输入错误", str(e))
            return

        self.bf_btn.setEnabled(False)
        self.bf_result.setText("正在暴力破解中，请稍候...")

        self.bf_thread = BruteForceThread(pairs)
        self.bf_thread.result_ready.connect(self.show_bruteforce_result)
        self.bf_thread.start()

    def show_bruteforce_result(self, keys, dt):
        self.bf_btn.setEnabled(True)

        if not keys:
            text = f"未找到密钥 | 用时 {dt:.6f}秒"
        else:
            lines = [
                f"找到 {len(keys)} 个密钥 | 用时 {dt:.6f}秒",
                "-" * 50
            ]
            show = keys[:50]
            for k in show:
                lines.append(f"十进制: {k:4d}    二进制: {k:010b}    十六进制: {k:03x}")
            if len(keys) > len(show):
                lines.append(f"... 其余 {len(keys) - len(show)} 个未显示")
            text = "\n".join(lines)

        self.bf_result.setText(text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SDESGUI()
    window.show()
    sys.exit(app.exec_())