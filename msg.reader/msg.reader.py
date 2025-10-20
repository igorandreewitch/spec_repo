from PyQt5 import QtWidgets, QtWebEngineWidgets, QtCore
from PyQt5.QtCore import QUrl
import extract_msg
import msg_parser
import os
import re
import tempfile
import sys
import webbrowser
import chardet
from ftfy import fix_text

def sniff_charset_from_html_bytes(b):
    if not isinstance(b, (bytes, bytearray)):
        return None
    head = b[:4096].lower()
    m = re.search(br'charset\s*=\s*["\']?([a-z0-9_\-]+)', head)
    if m:
        try:
            return m.group(1).decode('ascii', 'ignore')
        except:
            return None
    return None

def decode_bytes_robust(data, primary=None, html_hint=False):
    if isinstance(data, str):
        return fix_text(data)
    if not data:
        return ""
    if html_hint:
        meta = sniff_charset_from_html_bytes(data)
        if meta:
            try:
                return fix_text(data.decode(meta, errors='strict'))
            except:
                pass
    if primary:
        try:
            return fix_text(data.decode(primary, errors='strict'))
        except:
            pass
    for enc in ("utf-8", "cp1251", "windows-1251", "koi8-r", "iso-8859-5", "cp866", "mac_cyrillic", "latin1"):
        try:
            return fix_text(data.decode(enc, errors='strict'))
        except:
            continue
    try:
        det = chardet.detect(data) or {}
        enc = det.get("encoding")
        if enc:
            return fix_text(data.decode(enc, errors='ignore'))
    except:
        pass
    return fix_text(data.decode("utf-8", errors="ignore"))

class MsgViewer(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MSG HTML Viewer")
        self.resize(1100, 800)
        self.tabs = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tabs)
        self.html_browser = QtWebEngineWidgets.QWebEngineView()
        self.tabs.addTab(self.html_browser, "Письмо")
        self.attachments_scroll = QtWidgets.QScrollArea()
        self.attachments_scroll.setWidgetResizable(True)
        self.attachments_container = QtWidgets.QWidget()
        self.attachments_layout = QtWidgets.QVBoxLayout(self.attachments_container)
        self.attachments_scroll.setWidget(self.attachments_container)
        self.tabs.addTab(self.attachments_scroll, "Вложения")
        menu = self.menuBar().addMenu("Файл")
        open_action = menu.addAction("Открыть MSG")
        open_action.triggered.connect(self.select_msg)
        self.temp_dir = tempfile.mkdtemp()

    def clear_attachments(self):
        while self.attachments_layout.count():
            item = self.attachments_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def select_msg(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Открыть MSG", "", "MSG Files (*.msg)")
        if path:
            self.open_msg_from_path(path)

    def open_msg_from_path(self, path):
        self.clear_attachments()
        msg = extract_msg.Message(path)
        html = None
        if getattr(msg, "htmlBody", None):
            html = decode_bytes_robust(msg.htmlBody, getattr(msg, "codepage", None) or None, html_hint=True)
        if not html or len(html.strip()) == 0:
            try:
                parsed = msg_parser.MsgParser(path).extract()
            except:
                parsed = {}
            if parsed.get("body_html"):
                bh = parsed["body_html"]
                html = decode_bytes_robust(bh, None, html_hint=True)
            elif parsed.get("body_rtf"):
                bt = parsed.get("body_text") or ""
                html = "<pre>" + decode_bytes_robust(bt, None, html_hint=False) + "</pre>"
        if not html:
            body_txt = msg.body or (parsed.get("body_text") if isinstance(parsed, dict) else None) or ""
            html = "<pre>" + decode_bytes_robust(body_txt, None, html_hint=False) + "</pre>"

        for attach in msg.attachments:
            filename = attach.longFilename or attach.shortFilename
            if not filename:
                continue
            safe_name = os.path.basename(filename)
            file_path = os.path.join(self.temp_dir, safe_name)
            try:
                with open(file_path, "wb") as f:
                    f.write(attach.data)
            except:
                continue
            if getattr(attach, "cid", None):
                cid_clean = attach.cid.strip("<>")
                html = re.sub(rf'cid:{re.escape(cid_clean)}',
                              f"file:///{file_path.replace('\\', '/')}",
                              html, flags=re.IGNORECASE)
            basename = os.path.basename(safe_name)
            html = re.sub(rf'src=["\']{re.escape(basename)}["\']',
                          f'src="file:///{file_path.replace('\\', '/')}"',
                          html, flags=re.IGNORECASE)
            self.add_attachment_widget(safe_name, file_path)

        self.html_browser.setHtml(html, baseUrl=QtCore.QUrl.fromLocalFile(self.temp_dir + "/"))

    def add_attachment_widget(self, filename, file_path):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(widget)
        label = QtWidgets.QLabel(filename)
        label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        layout.addWidget(label)
        try:
            size = os.path.getsize(file_path)
            size_label = QtWidgets.QLabel(f"{size/1024:.1f} КБ")
        except:
            size_label = QtWidgets.QLabel("")
        layout.addWidget(size_label)
        btn_open = QtWidgets.QPushButton("Открыть")
        btn_open.clicked.connect(lambda: webbrowser.open(file_path))
        layout.addWidget(btn_open)
        self.attachments_layout.addWidget(widget)
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.attachments_layout.addWidget(line)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    viewer = MsgViewer()
    viewer.show()

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if os.path.isfile(file_path):
            viewer.open_msg_from_path(file_path)

    app.exec_()
