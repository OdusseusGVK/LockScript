import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, base64, tempfile, platform, subprocess, secrets, socket, threading, struct, webbrowser, time, zipfile, io

# ---------- Проверка библиотек ----------
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    AES_OK = True
except ImportError:
    AES_OK = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

# ---------- Константы ----------
DEFAULT_PASSWORD = "8f$#kL9@2mQp!x&7"
HEADER_SIMPLE = "LCK1:"
HEADER_STANDARD = "LCK2:"
HEADER_EXTENDED = "LCK3:"
HEADER_PASSWORD = "LCK4:"
HEADER_RICH = "LCK5:"          # rich-формат с изображениями
PBKDF2_ITER = 100_000
SALT_LEN = 16
NONCE_LEN = 12
APP_VERSION = "1.1"
AUTHOR = "OdusseusGVK"
AUTHOR_URL = "https://github.com/OdusseusGVK"
AUTOSAVE_INTERVAL = 10  # секунды

# ---------- Шифрование ----------
def _xor(data, key):
    kb = key.encode()
    return bytes([b ^ kb[i % len(kb)] for i, b in enumerate(data)])

def encrypt_simple(text, key):
    return HEADER_SIMPLE + base64.b64encode(_xor(text.encode(), key)).decode()

def decrypt_simple(pkt, key):
    return _xor(base64.b64decode(pkt[len(HEADER_SIMPLE):]), key).decode()

def derive_key(pwd, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITER).derive(pwd.encode())

def encrypt_standard(text, key):
    s = secrets.token_bytes(SALT_LEN)
    dk = derive_key(key, s)
    n = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(dk).encrypt(n, text.encode(), None)
    return HEADER_STANDARD + base64.b64encode(s + n + ct).decode()

def decrypt_standard(pkt, key):
    raw = base64.b64decode(pkt[len(HEADER_STANDARD):])
    s, n = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN]
    return AESGCM(derive_key(key, s)).decrypt(n, raw[SALT_LEN+NONCE_LEN:], None).decode()

def encrypt_extended(text, key):
    xd = _xor(text.encode(), key)
    s = secrets.token_bytes(SALT_LEN)
    dk = derive_key(key, s)
    n = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(dk).encrypt(n, xd, None)
    return HEADER_EXTENDED + base64.b64encode(s + n + ct).decode()

def decrypt_extended(pkt, key):
    raw = base64.b64decode(pkt[len(HEADER_EXTENDED):])
    s, n = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN]
    xd = AESGCM(derive_key(key, s)).decrypt(n, raw[SALT_LEN+NONCE_LEN:], None)
    return _xor(xd, key).decode()

def encrypt_password(text, password):
    s = secrets.token_bytes(SALT_LEN)
    dk = derive_key(password, s)
    n = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(dk).encrypt(n, text.encode(), None)
    return HEADER_PASSWORD + base64.b64encode(s + n + ct).decode()

def decrypt_password(pkt, password):
    raw = base64.b64decode(pkt[len(HEADER_PASSWORD):])
    s, n = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN]
    return AESGCM(derive_key(password, s)).decrypt(n, raw[SALT_LEN+NONCE_LEN:], None).decode()

# ---------- Rich-формат (ZIP + AES) ----------
def encrypt_rich(text, images, key):
    """Упаковывает текст и изображения в ZIP, шифрует AES-GCM."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('content.txt', text)
        for idx, img_data in enumerate(images):
            zf.writestr(f'images/{idx}.png', img_data)
    raw_zip = buf.getvalue()
    s = secrets.token_bytes(SALT_LEN)
    dk = derive_key(key, s)
    n = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(dk).encrypt(n, raw_zip, None)
    packet = s + n + ct
    return HEADER_RICH + base64.b64encode(packet).decode()

def decrypt_rich(pkt, key):
    raw = base64.b64decode(pkt[len(HEADER_RICH):])
    s, n = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN]
    enc = raw[SALT_LEN+NONCE_LEN:]
    dk = derive_key(key, s)
    zip_data = AESGCM(dk).decrypt(n, enc, None)
    buf = io.BytesIO(zip_data)
    images = []
    text = ""
    with zipfile.ZipFile(buf, 'r') as zf:
        if 'content.txt' in zf.namelist():
            text = zf.read('content.txt').decode('utf-8')
        for name in zf.namelist():
            if name.startswith('images/'):
                images.append(zf.read(name))
    return text, images

# ---------- Сеть ----------
def send_raw_document(host, port, data: bytes):
    """Отправляет уже зашифрованные данные через сокет."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(10)
        sock.connect((host, port))
        sock.sendall(struct.pack('>I', len(data)) + data)
        return True
    except Exception as e:
        raise e
    finally:
        sock.close()

def receive_document(port, callback):
    def server_thread():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', port))
            sock.listen(1)
            sock.settimeout(30)
            conn, addr = sock.accept()
            raw_len = conn.recv(4)
            if not raw_len:
                raise Exception("Соединение разорвано")
            length = struct.unpack('>I', raw_len)[0]
            data = b''
            while len(data) < length:
                chunk = conn.recv(min(4096, length - len(data)))
                if not chunk:
                    raise Exception("Соединение разорвано")
                data += chunk
            conn.close()
            encrypted = data.decode()
            callback(encrypted, None)
        except Exception as e:
            callback(None, str(e))
        finally:
            sock.close()
    threading.Thread(target=server_thread, daemon=True).start()

# ---------- Диалоговые окна (без изменений) ----------
class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title="Введите пароль"):
        super().__init__(parent, bg='#1e1e2e')
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.configure(bg='#1e1e2e')
        frame = tk.Frame(self, bg='#252536', padx=20, pady=20)
        frame.pack()
        tk.Label(frame, text="ВВЕДИТЕ ПАРОЛЬ", bg='#252536', fg='#cdd6f4', font=('Segoe UI',9,'bold')).pack(pady=(0,5))
        self.pwd_var = tk.StringVar()
        self.entry = tk.Entry(frame, textvariable=self.pwd_var, show='●', width=30,
                              bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                              font=('Segoe UI',10), relief='flat', bd=8)
        self.entry.pack(pady=5)
        self.entry.focus_set()
        self.show_var = tk.BooleanVar()
        tk.Checkbutton(frame, text='Показать', variable=self.show_var,
                       command=lambda: self.entry.config(show='' if self.show_var.get() else '●'),
                       bg='#252536', fg='#a6adc8', selectcolor='#252536', activebackground='#252536').pack()
        btn_frame = tk.Frame(frame, bg='#252536')
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text='ОТМЕНА', bg='#45475a', fg='#cdd6f4', relief='flat', padx=20,
                  command=self.cancel).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text='ОК', bg='#cba6f7', fg='#1e1e2e', relief='flat', padx=20,
                  command=self.ok).pack(side=tk.LEFT, padx=5)
        self.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.cancel())
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width()-w)//2
        y = parent.winfo_rooty() + (parent.winfo_height()-h)//2
        self.geometry(f"+{x}+{y}")
        self.wait_window(self)
    def ok(self):
        self.result = self.pwd_var.get()
        self.destroy()
    def cancel(self):
        self.result = None
        self.destroy()

class EncryptionCardDialog(tk.Toplevel):
    def __init__(self, parent, has_images=False):
        super().__init__(parent, bg='#1e1e2e')
        self.title("Уровень защиты")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None   # (type, key)
        self.configure(bg='#1e1e2e')
        frame = tk.Frame(self, bg='#252536', padx=20, pady=20)
        frame.pack()
        tk.Label(frame, text="ВЫБЕРИТЕ УРОВЕНЬ ЗАЩИТЫ", bg='#252536', fg='#cdd6f4',
                 font=('Segoe UI',12,'bold')).pack(pady=10)
        cards_frame = tk.Frame(frame, bg='#252536')
        cards_frame.pack(pady=10)

        cards = [
            ("Простое", "🛡", "#a6e3a1", "Быстрое шифрование", 'simple'),
            ("Стандартное", "🔒", "#fab387", "Современный стандарт", 'standard'),
            ("Расширенное", "🏰", "#f38ba8", "Лучшее шифрование\nМаксимальная защита", 'extended'),
            ("С паролем", "🔑", "#cba6f7", "Шифрование паролем\nТолько для вас", 'password'),
        ]
        if has_images:
            cards = [
                ("Rich-документ", "📦", "#89b4fa", "Текст + изображения\nСовременный формат", 'rich'),
                ("Rich с паролем", "🔐", "#cba6f7", "Rich + пароль\nМаксимальная защита", 'rich_password')
            ]
            if not AES_OK:
                ttk.Label(frame, text="Для сохранения изображений требуется библиотека cryptography.\nУстановите её: pip install cryptography",
                          foreground='red').pack(pady=10)
                tk.Button(frame, text='ОТМЕНА', bg='#45475a', fg='#cdd6f4', relief='flat', padx=30,
                          command=lambda: self.set_result(None)).pack(pady=10)
                self.update_idletasks()
                self.wait_window()
                return

        for title, icon, color, desc, val in cards:
            card = tk.Frame(cards_frame, bg='#313244', width=130, height=180)
            card.pack(side=tk.LEFT, padx=5)
            card.pack_propagate(False)
            tk.Label(card, text=icon, bg='#313244', font=('Segoe UI',20)).pack(pady=(15,0))
            tk.Label(card, text=title, bg='#313244', fg=color, font=('Segoe UI',9,'bold')).pack()
            tk.Label(card, text=desc, bg='#313244', fg='#bac2de', font=('Segoe UI',7),
                     justify=tk.CENTER).pack(pady=5)
            card.bind('<Enter>', lambda e, c=card: c.config(bg='#45475a'))
            card.bind('<Leave>', lambda e, c=card: c.config(bg='#313244'))
            for w in [card] + card.winfo_children():
                w.bind('<Button-1>', lambda e, v=val: self.select(v))
            if not AES_OK and val in ('standard', 'extended', 'password', 'rich', 'rich_password'):
                card.config(state='disabled')
                for w in card.winfo_children():
                    w.config(fg='#585b70')
        tk.Button(frame, text='ОТМЕНА', bg='#45475a', fg='#cdd6f4', relief='flat', padx=30,
                  command=lambda: self.set_result(None)).pack(pady=10)
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width()-w)//2
        y = parent.winfo_rooty() + (parent.winfo_height()-h)//2
        self.geometry(f"+{x}+{y}")
        self.wait_window(self)
    def select(self, value):
        if value == 'password' or value == 'rich_password':
            dlg = PasswordDialog(self, "Придумайте пароль")
            if dlg.result:
                self.result = (value, dlg.result)
                self.destroy()
        elif value == 'rich':
            self.result = ('rich', DEFAULT_PASSWORD)
            self.destroy()
        else:
            self.result = (value, DEFAULT_PASSWORD)
            self.destroy()
    def set_result(self, value):
        self.result = value
        self.destroy()

class NetworkDialog(tk.Toplevel):
    def __init__(self, parent, mode='send'):
        super().__init__(parent, bg='#1e1e2e')
        self.title("Отправка LockScript" if mode=='send' else "Приём LockScript")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.mode = mode
        self.result = None
        self.configure(bg='#1e1e2e')
        frame = tk.Frame(self, bg='#252536', padx=20, pady=20)
        frame.pack()
        tk.Label(frame, text="ОТПРАВИТЬ ДОКУМЕНТ" if mode=='send' else "ПРИНЯТЬ ДОКУМЕНТ",
                 bg='#252536', fg='#cdd6f4', font=('Segoe UI',12,'bold')).pack(pady=10)
        if mode == 'send':
            tk.Label(frame, text="IP-адрес получателя:", bg='#252536', fg='#a6adc8', font=('Segoe UI',9)).pack(anchor='w')
            self.host_var = tk.StringVar(value='127.0.0.1')
            tk.Entry(frame, textvariable=self.host_var, bg='#313244', fg='#cdd6f4', relief='flat', font=('Segoe UI',10)).pack(fill=tk.X, pady=5)
        tk.Label(frame, text="Порт:", bg='#252536', fg='#a6adc8', font=('Segoe UI',9)).pack(anchor='w')
        self.port_var = tk.IntVar(value=55555)
        tk.Entry(frame, textvariable=self.port_var, bg='#313244', fg='#cdd6f4', relief='flat', font=('Segoe UI',10)).pack(fill=tk.X, pady=5)
        btn_frame = tk.Frame(frame, bg='#252536')
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text='ЗАПУСТИТЬ', bg='#cba6f7', fg='#1e1e2e', relief='flat', padx=30,
                  command=self.ok).pack()
        self.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.destroy())
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width()-w)//2
        y = parent.winfo_rooty() + (parent.winfo_height()-h)//2
        self.geometry(f"+{x}+{y}")
        self.wait_window(self)
    def ok(self):
        if self.mode == 'send':
            self.result = (self.host_var.get(), self.port_var.get())
        else:
            self.result = ('', self.port_var.get())
        self.destroy()

class FindReplaceDialog(tk.Toplevel):
    # ... (без изменений, полная версия дана в предыдущем ответе) ...
    pass  # полная реализация есть выше, опускаю для краткости

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind('<Enter>', self.enter)
        widget.bind('<Leave>', self.leave)
    def enter(self, event=None):
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", foreground="#000000",
                         relief=tk.SOLID, borderwidth=1,
                         font=("Segoe UI", "8", "normal"))
        label.pack(ipadx=1)
    def leave(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

# ---------- Главное приложение ----------
class LockScript:
    def __init__(self, root):
        self.root = root
        self.root.title("LockScript — Защищённые документы")
        self.root.geometry("1100x900")
        self.root.minsize(900, 600)
        self.dark = True
        self.font_family = tk.StringVar(value="Arial")
        self.font_size = tk.IntVar(value=12)
        self.font_combo = None
        self.size_combo = None
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_theme()
        self.main_container = tk.Frame(self.root, bg='#1e1e2e')
        self.main_container.pack(fill=tk.BOTH, expand=True)
        self.sidebar = tk.Frame(self.main_container, bg='#181825', width=50)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)
        self.create_sidebar_buttons()
        self.content = tk.Frame(self.main_container, bg='#1e1e2e')
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.toolbar = tk.Frame(self.content, bg='#181825', height=40)
        self.toolbar.pack(fill=tk.X)
        self.create_toolbar()
        self.notebook = ttk.Notebook(self.content)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tabs = []
        self.status_var = tk.StringVar(value="Готов | Слов: 0")
        status = tk.Frame(self.content, bg='#181825', height=25)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(status, textvariable=self.status_var, bg='#181825', fg='#a6adc8',
                 font=('Segoe UI',8), anchor=tk.W).pack(fill=tk.X, padx=10)
        self.tab_menu = tk.Menu(self.root, tearoff=0, bg='#313244', fg='#cdd6f4')
        self.tab_menu.add_command(label="Закрыть вкладку", command=self.close_tab)
        self.notebook.bind("<Button-3>", self.on_tab_right_click)
        self.bind_shortcuts()
        self.new_tab()
        if self.tabs:
            self.notebook.select(0)
        if DND_AVAILABLE:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.on_drop)
        self.autosave_timer = self.root.after(AUTOSAVE_INTERVAL * 1000, self.autosave)
        self.word_count_timer = self.root.after(1000, self.update_word_count)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ---------- Drag-and-drop ----------
    def on_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        for file in files:
            if file.lower().endswith('.lscript') or file.lower().endswith('.txt'):
                self.open_file(file)

    # ---------- Автосохранение ----------
    def autosave(self):
        for tab in self.tabs:
            if tab['path'] and self.check_unsaved(tab):
                content, images = self.extract_content_and_images(tab['text'])
                enc = tab['encryption']
                key = tab['key']
                if enc:
                    try:
                        encrypted = self._encrypt_tab_content(content, images, enc, key)
                        with open(tab['path'] + '.autosave', 'w', encoding='utf-8') as f:
                            f.write(encrypted)
                    except Exception:
                        pass
        self.autosave_timer = self.root.after(AUTOSAVE_INTERVAL * 1000, self.autosave)

    # ---------- Счётчик слов ----------
    def update_word_count(self):
        tab = self.current_tab
        if tab:
            content, _ = self.extract_content_and_images(tab['text'])
            words = len(content.split())
            self.status_var.set(f"Готов | Защита: {tab['encryption'] or 'не выбрана'} | Слов: {words}")
        self.word_count_timer = self.root.after(1000, self.update_word_count)

    # ---------- Индикатор изменений ----------
    def mark_changed(self, tab):
        if not tab['text'].edit_modified():
            return
        tab['changed'] = True
        self.update_tab_indicator(tab)
        tab['text'].edit_modified(False)

    def update_tab_indicator(self, tab):
        idx = self.tabs.index(tab)
        text = self.notebook.tab(idx, "text")
        if tab['changed']:
            if not text.startswith('*'):
                self.notebook.tab(idx, text='*' + text)
        else:
            if text.startswith('*'):
                self.notebook.tab(idx, text=text[1:])

    def clear_changed(self, tab):
        tab['changed'] = False
        self.update_tab_indicator(tab)

    # ---------- Горячие клавиши ----------
    def bind_shortcuts(self):
        root = self.root
        root.bind("<F1>", lambda e: self.show_hotkeys())
        root.bind("<F2>", lambda e: self.new_tab())
        root.bind("<F3>", lambda e: self.open_file())
        root.bind("<F5>", lambda e: self.save_file())
        root.bind("<F6>", lambda e: self.find_replace())
        root.bind("<F7>", lambda e: self.print_file())
        root.bind("<F8>", lambda e: self.close_tab())
        root.bind("<F9>", lambda e: self.save_as())
        root.bind("<F10>", lambda e: self.toggle_dark())
        root.bind("<F12>", lambda e: self.on_closing())

    # ---------- Темы ----------
    def apply_theme(self):
        if self.dark:
            bg, fg, entry_bg, entry_fg = '#1e1e2e', '#cdd6f4', '#313244', '#cdd6f4'
            self.style.configure('TNotebook', background='#1e1e2e', borderwidth=0)
            self.style.configure('TNotebook.Tab', background='#313244', foreground='#cdd6f4',
                                 padding=[15,5], font=('Segoe UI',9))
            self.style.map('TNotebook.Tab', background=[('selected', '#45475a')])
            self.style.configure('TFrame', background='#1e1e2e')
        else:
            bg, fg, entry_bg, entry_fg = '#f5f5f5', '#333333', '#ffffff', '#000000'
            self.style.configure('TNotebook', background='#f5f5f5')
            self.style.configure('TNotebook.Tab', background='#e0e0e0', foreground='#333', padding=[15,5])
            self.style.map('TNotebook.Tab', background=[('selected', '#ffffff')])
        self.root.option_add("*Text.Background", entry_bg)
        self.root.option_add("*Text.Foreground", entry_fg)

    def create_sidebar_buttons(self):
        buttons = [
            ("📄", "Новый документ (F2)", self.new_tab),
            ("📂", "Открыть (F3)", self.open_file),
            ("💾", "Сохранить (F5)", self.save_file),
            ("🔍", "Поиск и замена (F6)", self.find_replace),
            ("🖼", "Вставить изображение", self.insert_image),
            ("🌙", "Сменить тему (F10)", self.toggle_dark),
            ("📡", "Сеть (отправить/принять)", self.show_network_choice),
            ("⌨", "Горячие клавиши (F1)", self.show_hotkeys),
            ("ℹ", "О программе", self.show_about)
        ]
        for icon, tip, cmd in buttons:
            btn = tk.Label(self.sidebar, text=icon, bg='#181825', fg='#a6adc8', font=('Segoe UI',14))
            btn.pack(pady=8)
            btn.bind('<Button-1>', lambda e, c=cmd: c())
            btn.bind('<Enter>', lambda e, b=btn: b.config(fg='#cba6f7'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(fg='#a6adc8'))
            ToolTip(btn, tip)

    def create_toolbar(self):
        btns = [
            ("📄 Новый", self.new_tab), ("📂 Открыть", self.open_file), ("💾 Сохранить", self.save_file),
            ("🔍 Поиск", self.find_replace), ("🌙 Тема", self.toggle_dark),
            ("📡 Сеть", self.show_network_choice)
        ]
        for text, cmd in btns:
            tk.Button(self.toolbar, text=text, bg='#313244', fg='#cdd6f4', font=('Segoe UI',9),
                      relief='flat', padx=10, pady=3, command=cmd).pack(side=tk.LEFT, padx=2, pady=5)
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        ttk.Label(self.toolbar, text="Шрифт:").pack(side=tk.LEFT, padx=(5,2))
        self.font_combo = ttk.Combobox(self.toolbar, textvariable=self.font_family,
                                       values=["Arial", "Times New Roman", "Courier New", "Verdana", "Georgia"],
                                       state='readonly', width=15)
        self.font_combo.pack(side=tk.LEFT, padx=2)
        self.font_combo.bind('<<ComboboxSelected>>', lambda e: self.update_font())
        ttk.Label(self.toolbar, text="Размер:").pack(side=tk.LEFT, padx=(10,2))
        self.size_combo = ttk.Combobox(self.toolbar, textvariable=self.font_size,
                                       values=[8,9,10,11,12,14,16,18,20,24,28,32],
                                       state='readonly', width=4)
        self.size_combo.pack(side=tk.LEFT, padx=2)
        self.size_combo.bind('<<ComboboxSelected>>', lambda e: self.update_font())

    # ---------- Вкладки ----------
    def new_tab(self, content="", path=None, enc=None, key=None, images=None):
        frame = tk.Frame(self.notebook, bg='#1e1e2e')
        text = tk.Text(frame, wrap=tk.WORD, font=(self.font_family.get(), self.font_size.get()),
                       bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                       relief='flat', padx=10, pady=10, undo=True)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        if content:
            text.insert('1.0', content)
        # Вставляем изображения из байтов
        if images:
            for img_data in images:
                try:
                    img = tk.PhotoImage(data=img_data)
                    text.image_create(tk.INSERT, image=img)
                    if not hasattr(text, 'images'):
                        text.images = []
                    text.images.append(img)
                except Exception:
                    pass
        text.config(state=tk.NORMAL)
        text.edit_modified(False)
        title = os.path.basename(path) if path else "Новый документ"
        lock_icon = {"simple":"🛡","standard":"🔒","extended":"🏰","password":"🔑","rich":"📦","rich_password":"🔐"}.get(enc, "📄")
        tab = {'frame':frame, 'text':text, 'bookmarks':[], 'path':path,
               'saved_content':content, 'encryption':enc, 'key':key, 'changed':False}
        text.bind('<<Modified>>', lambda e, t=tab: self.mark_changed(t))
        self.tabs.append(tab)
        self.notebook.add(frame, text=f"{lock_icon} {title}")
        self.notebook.select(frame)
        words = len(content.split()) if content else 0
        self.status_var.set(f"Готов | Защита: {enc or 'не выбрана'} | Слов: {words}")

    @property
    def current_tab(self):
        idx = self.notebook.index(self.notebook.select())
        return self.tabs[idx] if 0 <= idx < len(self.tabs) else None

    def close_tab(self):
        if len(self.tabs) <= 1:
            return
        tab = self.current_tab
        if tab and self.check_unsaved(tab):
            res = messagebox.askyesnocancel("Сохранение", "Сохранить изменения?")
            if res is None:
                return
            if res:
                if not self.ensure_encryption(tab):
                    return
                if not self._save_tab(tab):
                    return
        idx = self.tabs.index(tab)
        self.tabs.remove(tab)
        self.notebook.forget(idx)

    def check_unsaved(self, tab):
        current_content, _ = self.extract_content_and_images(tab['text'])
        return current_content != tab['saved_content']

    def ensure_encryption(self, tab):
        if tab['encryption']:
            return True
        has_images = bool(tab['text'].image_names())
        dlg = EncryptionCardDialog(self.root, has_images=has_images)
        if dlg.result:
            enc, key = dlg.result
            tab['encryption'] = enc
            tab['key'] = key
            return True
        return False

    # ---------- Извлечение контента (текст + байты изображений) ----------
    def extract_content_and_images(self, text_widget):
        """Возвращает текст и список байтов изображений."""
        content = text_widget.get('1.0', tk.END).rstrip('\n')
        images = []
        if hasattr(text_widget, 'images'):
            # Собираем байты из заранее сохранённых данных
            for img_data in text_widget.images_data if hasattr(text_widget, 'images_data') else []:
                images.append(img_data)
        return content, images

    # ---------- Шифрование содержимого вкладки ----------
    def _encrypt_tab_content(self, content, images, enc, key):
        if enc.startswith('rich'):
            return encrypt_rich(content, images, key)
        else:
            if images:
                messagebox.showwarning("Предупреждение", "Документ содержит изображения, но выбранный метод не поддерживает их. Будет сохранён только текст.")
            encryptors = {
                'simple': lambda t: encrypt_simple(t, key or DEFAULT_PASSWORD),
                'standard': lambda t: encrypt_standard(t, key or DEFAULT_PASSWORD),
                'extended': lambda t: encrypt_extended(t, key or DEFAULT_PASSWORD),
                'password': lambda t: encrypt_password(t, key)
            }
            return encryptors[enc](content)

    # ---------- Сохранение и открытие ----------
    def save_file(self):
        tab = self.current_tab
        if not tab:
            return
        if tab['path'] and tab['encryption']:
            self._save_tab(tab)
        else:
            self.save_as()

    def save_as(self):
        tab = self.current_tab
        if not tab:
            return
        path = filedialog.asksaveasfilename(defaultextension=".lscript", filetypes=[("LockScript", "*.lscript")])
        if not path:
            return
        if not self.ensure_encryption(tab):
            return
        tab['path'] = path
        self._save_tab(tab)

    def _save_tab(self, tab):
        content, images = self.extract_content_and_images(tab['text'])
        enc = tab['encryption']
        key = tab['key'] or DEFAULT_PASSWORD
        if not enc:
            messagebox.showerror("Ошибка", "Тип шифрования не выбран.")
            return False
        try:
            encrypted = self._encrypt_tab_content(content, images, enc, key)
            with open(tab['path'], 'w', encoding='utf-8') as f:
                f.write(encrypted)
            tab['saved_content'] = content
            self.clear_changed(tab)
            words = len(content.split())
            self.status_var.set(f"Сохранено | Защита: {enc} | Слов: {words}")
            lock_icon = {"simple":"🛡","standard":"🔒","extended":"🏰","password":"🔑","rich":"📦","rich_password":"🔐"}.get(enc, "📄")
            idx = self.tabs.index(tab)
            self.notebook.tab(idx, text=f"{lock_icon} {os.path.basename(tab['path'])}")
            autosave_path = tab['path'] + '.autosave'
            if os.path.exists(autosave_path):
                os.remove(autosave_path)
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return False

    def open_file(self, path=None):
        if not path:
            path = filedialog.askopenfilename(filetypes=[("LockScript", "*.lscript"), ("Текст", "*.txt")])
        if not path or not os.path.exists(path):
            return
        autosave_path = path + '.autosave'
        if os.path.exists(autosave_path) and os.path.getmtime(autosave_path) > os.path.getmtime(path):
            if messagebox.askyesno("Автосохранение", "Найдена более новая автосохранённая версия. Открыть её?"):
                path = autosave_path
        with open(path, encoding='utf-8') as f:
            raw = f.read()
        content, enc, key, images = "", None, None, []
        if raw.startswith(HEADER_RICH):
            # Пробуем расшифровать с DEFAULT_PASSWORD
            try:
                content, images = decrypt_rich(raw, DEFAULT_PASSWORD)
                enc = 'rich'
                key = DEFAULT_PASSWORD
            except Exception:
                # Спрашиваем пароль
                dlg = PasswordDialog(self.root, "Введите пароль для расшифровки")
                if not dlg.result:
                    return
                try:
                    content, images = decrypt_rich(raw, dlg.result)
                    enc = 'rich_password'
                    key = dlg.result
                except Exception:
                    messagebox.showerror("Ошибка", "Неверный пароль или файл повреждён.")
                    return
        elif raw.startswith(HEADER_PASSWORD):
            dlg = PasswordDialog(self.root, "Введите пароль для расшифровки")
            if not dlg.result:
                return
            try:
                content = decrypt_password(raw, dlg.result)
                enc = 'password'
                key = dlg.result
            except Exception:
                messagebox.showerror("Ошибка", "Неверный пароль или файл повреждён.")
                return
        elif raw.startswith(HEADER_EXTENDED):
            content = decrypt_extended(raw, DEFAULT_PASSWORD)
            enc = 'extended'
            key = DEFAULT_PASSWORD
        elif raw.startswith(HEADER_STANDARD):
            content = decrypt_standard(raw, DEFAULT_PASSWORD)
            enc = 'standard'
            key = DEFAULT_PASSWORD
        elif raw.startswith(HEADER_SIMPLE):
            content = decrypt_simple(raw, DEFAULT_PASSWORD)
            enc = 'simple'
            key = DEFAULT_PASSWORD
        else:
            content = raw
        self.new_tab(content, path, enc, key, images)

    # ---------- Вставка изображения ----------
    def insert_image(self):
        text = self.current_tab['text'] if self.current_tab else None
        if not text:
            return
        path = filedialog.askopenfilename(filetypes=[("Изображения", "*.png *.jpg *.jpeg *.gif *.bmp")])
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                img_data = f.read()
            img = tk.PhotoImage(data=img_data)
            # Масштабирование под ширину виджета
            max_width = text.winfo_width()
            if max_width > 1 and img.width() > max_width:
                factor = img.width() / max_width
                img = img.subsample(int(factor) if factor >= 1 else 1)
            text.image_create(tk.INSERT, image=img)
            if not hasattr(text, 'images'):
                text.images = []
            if not hasattr(text, 'images_data'):
                text.images_data = []
            text.images.append(img)
            text.images_data.append(img_data)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось вставить изображение: {e}")

    # ---------- Сеть ----------
    def show_network_choice(self):
        dlg = tk.Toplevel(self.root, bg='#1e1e2e')
        dlg.title("Сеть LockScript")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.configure(bg='#1e1e2e')
        frame = tk.Frame(dlg, bg='#252536', padx=30, pady=30)
        frame.pack()
        tk.Label(frame, text="ВЫБЕРИТЕ ДЕЙСТВИЕ", bg='#252536', fg='#cdd6f4',
                 font=('Segoe UI',12,'bold')).pack(pady=(0,20))
        cards_frame = tk.Frame(frame, bg='#252536')
        cards_frame.pack()
        send_card = tk.Frame(cards_frame, bg='#313244', width=140, height=180)
        send_card.pack(side=tk.LEFT, padx=10)
        send_card.pack_propagate(False)
        tk.Label(send_card, text="📤", bg='#313244', font=('Segoe UI',24)).pack(pady=(20,5))
        tk.Label(send_card, text="Передать", bg='#313244', fg='#a6e3a1', font=('Segoe UI',10,'bold')).pack()
        tk.Label(send_card, text="Отправить документ\nна другой компьютер", bg='#313244', fg='#bac2de',
                 font=('Segoe UI',7), justify=tk.CENTER).pack(pady=5)
        send_card.bind('<Enter>', lambda e, c=send_card: c.config(bg='#45475a'))
        send_card.bind('<Leave>', lambda e, c=send_card: c.config(bg='#313244'))
        for w in [send_card] + send_card.winfo_children():
            w.bind('<Button-1>', lambda e: (dlg.destroy(), self.send_document()))
        recv_card = tk.Frame(cards_frame, bg='#313244', width=140, height=180)
        recv_card.pack(side=tk.LEFT, padx=10)
        recv_card.pack_propagate(False)
        tk.Label(recv_card, text="📥", bg='#313244', font=('Segoe UI',24)).pack(pady=(20,5))
        tk.Label(recv_card, text="Получить", bg='#313244', fg='#fab387', font=('Segoe UI',10,'bold')).pack()
        tk.Label(recv_card, text="Принять документ\nот другого компьютера", bg='#313244', fg='#bac2de',
                 font=('Segoe UI',7), justify=tk.CENTER).pack(pady=5)
        recv_card.bind('<Enter>', lambda e, c=recv_card: c.config(bg='#45475a'))
        recv_card.bind('<Leave>', lambda e, c=recv_card: c.config(bg='#313244'))
        for w in [recv_card] + recv_card.winfo_children():
            w.bind('<Button-1>', lambda e: (dlg.destroy(), self.receive_document()))
        dlg.update_idletasks()
        w, h = dlg.winfo_width(), dlg.winfo_height()
        x = self.root.winfo_rootx() + (self.root.winfo_width()-w)//2
        y = self.root.winfo_rooty() + (self.root.winfo_height()-h)//2
        dlg.geometry(f"+{x}+{y}")
        dlg.wait_window()

    def send_document(self):
        tab = self.current_tab
        if not tab:
            return
        if not self.ensure_encryption(tab):
            return
        dlg = NetworkDialog(self.root, 'send')
        if not dlg.result:
            return
        host, port = dlg.result
        content, images = self.extract_content_and_images(tab['text'])
        enc = tab['encryption']
        key = tab['key'] or DEFAULT_PASSWORD
        try:
            encrypted = self._encrypt_tab_content(content, images, enc, key)
            send_raw_document(host, port, encrypted.encode('utf-8'))
            messagebox.showinfo("Успех", f"Документ отправлен на {host}:{port}")
            self.status_var.set(f"Отправлено на {host}:{port}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось отправить: {e}")

    def receive_document(self):
        dlg = NetworkDialog(self.root, 'receive')
        if not dlg.result:
            return
        _, port = dlg.result
        self.status_var.set(f"Ожидание подключения на порту {port}...")
        def on_received(encrypted, error=None):
            self.root.after(0, lambda: self._handle_received(encrypted, error))
        receive_document(port, on_received)

    def _handle_received(self, encrypted, error=None):
        if error:
            messagebox.showerror("Ошибка", f"Не удалось принять: {error}")
            self.status_var.set("Ошибка приёма")
            return
        # Повторяем логику открытия файла
        content, enc, key, images = "", None, None, []
        if encrypted.startswith(HEADER_RICH):
            try:
                content, images = decrypt_rich(encrypted, DEFAULT_PASSWORD)
                enc = 'rich'
                key = DEFAULT_PASSWORD
            except Exception:
                dlg = PasswordDialog(self.root, "Введите пароль для расшифровки")
                if not dlg.result:
                    return
                try:
                    content, images = decrypt_rich(encrypted, dlg.result)
                    enc = 'rich_password'
                    key = dlg.result
                except Exception:
                    messagebox.showerror("Ошибка", "Неверный пароль или файл повреждён.")
                    return
        elif encrypted.startswith(HEADER_PASSWORD):
            dlg = PasswordDialog(self.root, "Введите пароль для расшифровки")
            if not dlg.result:
                return
            try:
                content = decrypt_password(encrypted, dlg.result)
                enc = 'password'
                key = dlg.result
            except Exception:
                messagebox.showerror("Ошибка", "Неверный пароль или файл повреждён.")
                return
        elif encrypted.startswith(HEADER_EXTENDED):
            content = decrypt_extended(encrypted, DEFAULT_PASSWORD)
            enc = 'extended'
            key = DEFAULT_PASSWORD
        elif encrypted.startswith(HEADER_STANDARD):
            content = decrypt_standard(encrypted, DEFAULT_PASSWORD)
            enc = 'standard'
            key = DEFAULT_PASSWORD
        elif encrypted.startswith(HEADER_SIMPLE):
            content = decrypt_simple(encrypted, DEFAULT_PASSWORD)
            enc = 'simple'
            key = DEFAULT_PASSWORD
        else:
            content = encrypted
        self.new_tab(content, enc=enc, key=key, images=images)
        self.status_var.set("Документ принят")
        messagebox.showinfo("Успех", "Документ успешно принят и открыт")

    # ---------- Остальные функции ----------
    def toggle_dark(self):
        self.dark = not self.dark
        self.apply_theme()
        for tab in self.tabs:
            bg = '#313244' if self.dark else 'white'
            fg = '#cdd6f4' if self.dark else 'black'
            tab['text'].config(bg=bg, fg=fg)
        if self.font_combo:
            self.font_combo.set(self.font_family.get())
        if self.size_combo:
            self.size_combo.set(str(self.font_size.get()))

    def find_replace(self):
        text = self.current_tab['text'] if self.current_tab else None
        if text:
            FindReplaceDialog(self.root, text)

    def print_file(self):
        tab = self.current_tab
        if not tab:
            return
        content, _ = self.extract_content_and_images(tab['text'])
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            if platform.system() == 'Windows':
                os.startfile(tmp_path, "print")
            else:
                subprocess.run(["lp", tmp_path])
            self.status_var.set("Документ отправлен на печать.")
        except Exception as e:
            messagebox.showerror("Ошибка печати", str(e))

    def show_hotkeys(self):
        hotkeys = (
            "F1  — Справка\n"
            "F2  — Новый документ\n"
            "F3  — Открыть\n"
            "F5  — Сохранить\n"
            "F6  — Поиск и замена\n"
            "F7  — Печать\n"
            "F8  — Закрыть вкладку\n"
            "F9  — Сохранить как\n"
            "F10 — Тёмная тема\n"
            "F12 — Выход"
        )
        messagebox.showinfo("Горячие клавиши", hotkeys)

    def show_about(self):
        dlg = tk.Toplevel(self.root, bg='#1e1e2e')
        dlg.title("О программе")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        frame = tk.Frame(dlg, bg='#252536', padx=30, pady=20)
        frame.pack()
        tk.Label(frame, text="LockScript", bg='#252536', fg='#cdd6f4', font=('Segoe UI', 16, 'bold')).pack()
        tk.Label(frame, text=f"Версия {APP_VERSION}", bg='#252536', fg='#a6adc8', font=('Segoe UI', 10)).pack(pady=(0,10))
        tk.Label(frame, text="Инструмент для создания и обмена\nзашифрованными документами.", bg='#252536', fg='#bac2de',
                 font=('Segoe UI', 9), justify=tk.CENTER).pack(pady=(0,10))
        tk.Label(frame, text=f"Создатель: {AUTHOR}", bg='#252536', fg='#a6adc8', font=('Segoe UI', 10)).pack()
        link = tk.Label(frame, text="Ссылка", bg='#252536', fg='#cba6f7', font=('Segoe UI', 10, 'underline'))
        link.pack(pady=5)
        link.bind("<Button-1>", lambda e: webbrowser.open(AUTHOR_URL))
        tk.Button(frame, text="Закрыть", bg='#45475a', fg='#cdd6f4', relief='flat', command=dlg.destroy).pack(pady=10)
        dlg.update_idletasks()
        w, h = dlg.winfo_width(), dlg.winfo_height()
        x = self.root.winfo_rootx() + (self.root.winfo_width()-w)//2
        y = self.root.winfo_rooty() + (self.root.winfo_height()-h)//2
        dlg.geometry(f"+{x}+{y}")
        dlg.wait_window()

    def on_tab_right_click(self, event):
        idx = self.notebook.tk.call(self.notebook._w, "identify", "tab", event.x, event.y)
        if idx != '':
            self.notebook.select(int(idx))
            self.tab_menu.post(event.x_root, event.y_root)

    def on_closing(self):
        for tab in self.tabs:
            if self.check_unsaved(tab):
                self.notebook.select(self.tabs.index(tab))
                res = messagebox.askyesnocancel("Сохранение", "Сохранить изменения?")
                if res is None:
                    return
                if res:
                    if not self.ensure_encryption(tab):
                        return
                    if not self._save_tab(tab):
                        return
        self.root.destroy()

# ---------- Запуск ----------
if __name__ == "__main__":
    if DND_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.title("LockScript")
    root.geometry("400x200")
    root.update()
    app = LockScript(root)
    root.mainloop()
