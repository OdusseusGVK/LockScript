import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import os, json, base64, tempfile, platform, subprocess, secrets, socket, threading, struct, webbrowser

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    AES_OK = True
except ImportError:
    AES_OK = False

PASSWORD = "8f$#kL9@2mQp!x&7"
HEADER_SIMPLE = "LCK1:"
HEADER_STANDARD = "LCK2:"
HEADER_EXTENDED = "LCK3:"
RECENT_PATH = "recent_files.json"
MAX_RECENT = 5
PBKDF2_ITER = 100_000
SALT_LEN = 16
NONCE_LEN = 12
APP_VERSION = "1.0"
AUTHOR = "OdusseusGVK"
AUTHOR_URL = "https://github.com/OdusseusGVK"

def _xor(data, key):
    kb = key.encode()
    return bytes([b ^ kb[i % len(kb)] for i, b in enumerate(data)])

def encrypt_simple(text):
    return HEADER_SIMPLE + base64.b64encode(_xor(text.encode(), PASSWORD)).decode()

def decrypt_simple(pkt):
    return _xor(base64.b64decode(pkt[len(HEADER_SIMPLE):]), PASSWORD).decode()

def derive_key(pwd, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITER).derive(pwd.encode())

def encrypt_standard(text):
    s = secrets.token_bytes(SALT_LEN)
    key = derive_key(PASSWORD, s)
    n = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(n, text.encode(), None)
    return HEADER_STANDARD + base64.b64encode(s + n + ct).decode()

def decrypt_standard(pkt):
    raw = base64.b64decode(pkt[len(HEADER_STANDARD):])
    s, n = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN]
    return AESGCM(derive_key(PASSWORD, s)).decrypt(n, raw[SALT_LEN+NONCE_LEN:], None).decode()

def encrypt_extended(text):
    xd = _xor(text.encode(), PASSWORD)
    s = secrets.token_bytes(SALT_LEN)
    key = derive_key(PASSWORD, s)
    n = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(n, xd, None)
    return HEADER_EXTENDED + base64.b64encode(s + n + ct).decode()

def decrypt_extended(pkt):
    raw = base64.b64decode(pkt[len(HEADER_EXTENDED):])
    s, n = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN]
    xd = AESGCM(derive_key(PASSWORD, s)).decrypt(n, raw[SALT_LEN+NONCE_LEN:], None)
    return _xor(xd, PASSWORD).decode()

def send_document(host, port, content, encryption):
    encryptors = {'simple': encrypt_simple, 'standard': encrypt_standard, 'extended': encrypt_extended}
    encrypted = encryptors[encryption](content).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(10)
        sock.connect((host, port))
        sock.sendall(struct.pack('>I', len(encrypted)) + encrypted)
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
            if encrypted.startswith(HEADER_EXTENDED):
                decrypted = decrypt_extended(encrypted)
            elif encrypted.startswith(HEADER_STANDARD):
                decrypted = decrypt_standard(encrypted)
            elif encrypted.startswith(HEADER_SIMPLE):
                decrypted = decrypt_simple(encrypted)
            else:
                raise Exception("Неизвестный формат данных")
            callback(decrypted, None)
        except Exception as e:
            callback(None, str(e))
        finally:
            sock.close()
    threading.Thread(target=server_thread, daemon=True).start()

class EncryptionCardDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent, bg='#1e1e2e')
        self.title("Уровень защиты")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
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
            ("Расширенное", "🏰", "#f38ba8", "Лучшее шифрование\nМаксимальная защита", 'extended')
        ]
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
            if not AES_OK and val != 'simple':
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
        self.set_result(value)
    def set_result(self, value):
        self.result = value; self.destroy()

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
    def __init__(self, parent, text_widget):
        super().__init__(parent, bg='#1e1e2e')
        self.title("Поиск и замена")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.text_widget = text_widget
        self.last_find_pos = '1.0'
        self.configure(bg='#1e1e2e')
        frame = tk.Frame(self, bg='#252536', padx=20, pady=20)
        frame.pack()
        tk.Label(frame, text="Найти:", bg='#252536', fg='#cdd6f4', font=('Segoe UI',9)).grid(row=0, column=0, sticky='e')
        self.find_entry = tk.Entry(frame, width=25, bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4', relief='flat', font=('Segoe UI',10))
        self.find_entry.grid(row=0, column=1, padx=5, pady=2)
        self.find_entry.focus_set()
        tk.Label(frame, text="Заменить на:", bg='#252536', fg='#cdd6f4', font=('Segoe UI',9)).grid(row=1, column=0, sticky='e')
        self.replace_entry = tk.Entry(frame, width=25, bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4', relief='flat', font=('Segoe UI',10))
        self.replace_entry.grid(row=1, column=1, padx=5, pady=2)
        btn_frame = tk.Frame(frame, bg='#252536')
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        tk.Button(btn_frame, text="Найти далее", bg='#45475a', fg='#cdd6f4', relief='flat', padx=10, command=self.find_next).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Заменить", bg='#45475a', fg='#cdd6f4', relief='flat', padx=10, command=self.replace_one).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Заменить все", bg='#45475a', fg='#cdd6f4', relief='flat', padx=10, command=self.replace_all).pack(side=tk.LEFT, padx=2)
        self.bind('<Return>', lambda e: self.find_next())
        self.bind('<Escape>', lambda e: self.destroy())
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width()-w)//2
        y = parent.winfo_rooty() + (parent.winfo_height()-h)//2
        self.geometry(f"+{x}+{y}")
    def find_next(self):
        term = self.find_entry.get()
        if not term:
            return
        pos = self.text_widget.search(term, self.last_find_pos, stopindex=tk.END)
        if pos:
            self.text_widget.mark_set(tk.INSERT, pos)
            self.text_widget.see(pos)
            self.text_widget.tag_remove(tk.SEL, '1.0', tk.END)
            self.text_widget.tag_add(tk.SEL, pos, f"{pos}+{len(term)}c")
            self.last_find_pos = f"{pos}+{len(term)}c"
        else:
            messagebox.showinfo("Поиск", "Текст не найден.")
            self.last_find_pos = '1.0'
    def replace_one(self):
        if self.text_widget.tag_ranges(tk.SEL):
            self.text_widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
            self.text_widget.insert(tk.SEL_FIRST, self.replace_entry.get())
        self.find_next()
    def replace_all(self):
        term = self.find_entry.get()
        repl = self.replace_entry.get()
        if not term:
            return
        content = self.text_widget.get('1.0', tk.END)
        new_content = content.replace(term, repl)
        self.text_widget.delete('1.0', tk.END)
        self.text_widget.insert('1.0', new_content)

class LockScript:
    def __init__(self, root):
        self.root = root
        self.root.title("LockScript")
        self.root.geometry("1100x800")
        self.root.minsize(900, 600)
        self.dark = True
        self.font_family = tk.StringVar(value="Arial")
        self.font_size = tk.IntVar(value=12)
        self.recent = load_recent()
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_theme()
        self.main_container = tk.Frame(self.root, bg='#1e1e2e')
        self.main_container.pack(fill=tk.BOTH, expand=True)
        # Боковая панель
        self.sidebar = tk.Frame(self.main_container, bg='#181825', width=50)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)
        self.create_sidebar_buttons()
        # Основная область
        self.content = tk.Frame(self.main_container, bg='#1e1e2e')
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.toolbar = tk.Frame(self.content, bg='#181825', height=40)
        self.toolbar.pack(fill=tk.X)
        self.create_toolbar()
        self.notebook = ttk.Notebook(self.content)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tabs = []
        self.status_var = tk.StringVar(value="Готов | Защита: не выбрана")
        status = tk.Frame(self.content, bg='#181825', height=25)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(status, textvariable=self.status_var, bg='#181825', fg='#a6adc8',
                 font=('Segoe UI',8), anchor=tk.W).pack(fill=tk.X, padx=10)
        self.create_menu()
        self.tab_menu = tk.Menu(self.root, tearoff=0, bg='#313244', fg='#cdd6f4')
        self.tab_menu.add_command(label="Закрыть вкладку", command=self.close_tab)
        self.notebook.bind("<Button-3>", self.on_tab_right_click)
        self.bind_shortcuts()
        self.new_tab()
        if self.tabs:
            self.notebook.select(0)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def bind_shortcuts(self):
        root = self.root
        root.bind("<Control-n>", lambda e: self.new_tab())
        root.bind("<Control-o>", lambda e: self.open_file())
        root.bind("<Control-s>", lambda e: self.save_file())
        root.bind("<Control-Shift-s>", lambda e: self.save_as())
        root.bind("<Control-p>", lambda e: self.print_file())
        root.bind("<Control-f>", lambda e: self.find_replace())
        root.bind("<Control-w>", lambda e: self.close_tab())
        root.bind("<Control-c>", lambda e: self.safe_event("<<Copy>>"))
        root.bind("<Control-x>", lambda e: self.safe_event("<<Cut>>"))
        root.bind("<Control-v>", lambda e: self.safe_event("<<Paste>>"))
        root.bind("<Control-a>", lambda e: self.safe_event("<<SelectAll>>"))
        root.bind("<Control-z>", lambda e: self.safe_event("<<Undo>>"))
        root.bind("<Control-y>", lambda e: self.safe_event("<<Redo>>"))
        root.bind("<F1>", lambda e: self.show_hotkeys())

    def safe_event(self, event):
        tab = self.current_tab
        if tab and tab['text']:
            tab['text'].event_generate(event)

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
        icons = [
            ("📄", self.new_tab), ("📂", self.open_file), ("💾", self.save_file),
            ("🔍", self.find_replace), ("🌙", self.toggle_dark),
            ("📡", self.show_network_menu),
            (" ⌨️", self.show_hotkeys), (" ℹ️", self.show_about)
        ]
        for icon, cmd in icons:
            btn = tk.Label(self.sidebar, text=icon, bg='#181825', fg='#a6adc8', font=('Segoe UI',14))
            btn.pack(pady=8)
            btn.bind('<Button-1>', lambda e, c=cmd: c())
            btn.bind('<Enter>', lambda e, b=btn: b.config(fg='#cba6f7'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(fg='#a6adc8'))

    def create_toolbar(self):
        btns = [
            ("📄 Новый", self.new_tab), ("📂 Открыть", self.open_file), ("💾 Сохранить", self.save_file),
            ("🔍 Поиск", self.find_replace), ("🌙 Тема", self.toggle_dark),
            ("📡 Сеть", self.show_network_menu)
        ]
        for text, cmd in btns:
            tk.Button(self.toolbar, text=text, bg='#313244', fg='#cdd6f4', font=('Segoe UI',9),
                      relief='flat', padx=10, pady=3, command=cmd).pack(side=tk.LEFT, padx=2, pady=5)

    def create_menu(self):
        menubar = tk.Menu(self.root, bg='#313244', fg='#cdd6f4', activebackground='#45475a')
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0, bg='#313244', fg='#cdd6f4')
        menubar.add_cascade(label="Файл", menu=file_menu)
        for label, cmd, acc in [
            ("Новый", self.new_tab, "Ctrl+N"),
            ("Открыть", self.open_file, "Ctrl+O"),
            ("Сохранить", self.save_file, "Ctrl+S"),
            ("Сохранить как", self.save_as, "Ctrl+Shift+S"),
            ("Печать", self.print_file, "Ctrl+P"),
            ("Выход", self.on_closing, "Ctrl+Q")
        ]:
            file_menu.add_command(label=label, command=cmd, accelerator=acc)
        self.recent_menu = tk.Menu(file_menu, tearoff=0, bg='#313244', fg='#cdd6f4')
        file_menu.add_cascade(label="Недавние", menu=self.recent_menu)
        self.update_recent_menu()

        edit_menu = tk.Menu(menubar, tearoff=0, bg='#313244', fg='#cdd6f4')
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Вырезать", command=lambda: self.safe_event("<<Cut>>"), accelerator="Ctrl+X")
        edit_menu.add_command(label="Копировать", command=lambda: self.safe_event("<<Copy>>"), accelerator="Ctrl+C")
        edit_menu.add_command(label="Вставить", command=lambda: self.safe_event("<<Paste>>"), accelerator="Ctrl+V")
        edit_menu.add_separator()
        edit_menu.add_command(label="Поиск и замена", command=self.find_replace, accelerator="Ctrl+F")

        view_menu = tk.Menu(menubar, tearoff=0, bg='#313244', fg='#cdd6f4')
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_command(label="Тёмная тема", command=self.toggle_dark, accelerator="Ctrl+T")

        network_menu = tk.Menu(menubar, tearoff=0, bg='#313244', fg='#cdd6f4')
        menubar.add_cascade(label="Сеть", menu=network_menu)
        network_menu.add_command(label="Отправить документ...", command=self.send_document)
        network_menu.add_command(label="Принять документ...", command=self.receive_document)

        help_menu = tk.Menu(menubar, tearoff=0, bg='#313244', fg='#cdd6f4')
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="Горячие клавиши", command=self.show_hotkeys, accelerator="F1")
        help_menu.add_command(label="О программе", command=self.show_about)

    def update_recent_menu(self):
        self.recent_menu.delete(0, tk.END)
        if not self.recent:
            self.recent_menu.add_command(label="(пусто)", state=tk.DISABLED)
        else:
            for f in self.recent:
                self.recent_menu.add_command(label=os.path.basename(f), command=lambda p=f: self.open_recent(p))

    def new_tab(self, content="", path=None, enc=None):
        frame = tk.Frame(self.notebook, bg='#1e1e2e')
        text = tk.Text(frame, wrap=tk.WORD, font=(self.font_family.get(), self.font_size.get()),
                       bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                       relief='flat', padx=10, pady=10, undo=True)
        text.pack(fill=tk.BOTH, expand=True)
        if content:
            text.insert('1.0', content)
        text.config(state=tk.NORMAL)
        title = os.path.basename(path) if path else "Новый документ"
        lock_icon = {"simple":"🛡️","standard":"🔒","extended":"🏰"}.get(enc, "📄")
        self.tabs.append({'frame':frame, 'text':text, 'bookmarks':[], 'path':path,
                          'saved_content':content, 'encryption':enc})
        self.notebook.add(frame, text=f"{lock_icon} {title}")
        self.notebook.select(frame)
        self.status_var.set(f"Защита: {enc or 'не выбрана'}")

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
        return tab['text'].get('1.0', tk.END).rstrip('\n') != tab['saved_content']

    def ensure_encryption(self, tab):
        if tab['encryption']:
            return True
        dlg = EncryptionCardDialog(self.root)
        if dlg.result:
            tab['encryption'] = dlg.result
            return True
        return False

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
        content = tab['text'].get('1.0', tk.END).rstrip('\n')
        enc = tab['encryption']
        if not enc:
            messagebox.showerror("Ошибка", "Тип шифрования не выбран.")
            return False
        encryptors = {'simple': encrypt_simple, 'standard': encrypt_standard, 'extended': encrypt_extended}
        try:
            with open(tab['path'], 'w', encoding='utf-8') as f:
                f.write(encryptors[enc](content))
            tab['saved_content'] = content
            self.add_recent(tab['path'])
            self.status_var.set(f"Сохранено | Защита: {enc}")
            lock_icon = {"simple":"🛡️","standard":"🔒","extended":"🏰"}.get(enc, "📄")
            idx = self.tabs.index(tab)
            self.notebook.tab(idx, text=f"{lock_icon} {os.path.basename(tab['path'])}")
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return False

    def open_file(self, path=None):
        if not path:
            path = filedialog.askopenfilename(filetypes=[("LockScript", "*.lscript"), ("Текст", "*.txt")])
        if not path:
            return
        if not os.path.exists(path):
            messagebox.showerror("Ошибка", f"Файл не найден: {path}")
            self.recent = [f for f in self.recent if f != path]
            save_recent(self.recent)
            self.update_recent_menu()
            return
        with open(path, encoding='utf-8') as f:
            raw = f.read()
        content, enc = "", None
        if raw.startswith(HEADER_EXTENDED):
            content, enc = decrypt_extended(raw), 'extended'
        elif raw.startswith(HEADER_STANDARD):
            content, enc = decrypt_standard(raw), 'standard'
        elif raw.startswith(HEADER_SIMPLE):
            content, enc = decrypt_simple(raw), 'simple'
        else:
            content = raw
        self.new_tab(content, path, enc)
        self.add_recent(path)

    def open_recent(self, path):
        self.open_file(path)

    def add_recent(self, path):
        if path in self.recent:
            self.recent.remove(path)
        self.recent.insert(0, path)
        self.recent = self.recent[:MAX_RECENT]
        save_recent(self.recent)
        self.update_recent_menu()

    def show_network_menu(self):
        choice = simpledialog.askstring("Сеть", "Введите 'send' для отправки или 'receive' для приёма:")
        if choice == 'send':
            self.send_document()
        elif choice == 'receive':
            self.receive_document()

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
        try:
            send_document(host, port, tab['text'].get('1.0', tk.END).rstrip('\n'), tab['encryption'])
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
        def on_received(decrypted, error=None):
            self.root.after(0, lambda: self._handle_received(decrypted, error))
        receive_document(port, on_received)

    def _handle_received(self, decrypted, error=None):
        if error:
            messagebox.showerror("Ошибка", f"Не удалось принять: {error}")
            self.status_var.set("Ошибка приёма")
        else:
            self.new_tab(content=decrypted, enc=None)
            self.status_var.set("Документ принят")
            messagebox.showinfo("Успех", "Документ успешно принят и открыт")

    def toggle_dark(self):
        self.dark = not self.dark
        self.apply_theme()
        for tab in self.tabs:
            bg = '#313244' if self.dark else 'white'
            fg = '#cdd6f4' if self.dark else 'black'
            tab['text'].config(bg=bg, fg=fg)

    def find_replace(self):
        text = self.current_tab['text'] if self.current_tab else None
        if text:
            FindReplaceDialog(self.root, text)

    def print_file(self):
        tab = self.current_tab
        if not tab:
            return
        content = tab['text'].get('1.0', tk.END)
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
            "Ctrl+N — Новый документ\n"
            "Ctrl+O — Открыть\n"
            "Ctrl+S — Сохранить\n"
            "Ctrl+Shift+S — Сохранить как\n"
            "Ctrl+P — Печать\n"
            "Ctrl+W — Закрыть вкладку\n"
            "Ctrl+F — Поиск и замена\n"
            "Ctrl+C / Ctrl+X / Ctrl+V — Копировать / Вырезать / Вставить\n"
            "Ctrl+A — Выделить всё\n"
            "Ctrl+Z / Ctrl+Y — Отменить / Повторить\n"
            "F1 — Горячие клавиши"
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

def load_recent():
    if os.path.exists(RECENT_PATH):
        with open(RECENT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_recent(files):
    with open(RECENT_PATH, "w", encoding="utf-8") as f:
        json.dump(files, f, indent=2)

# ---------- Запуск ----------
if __name__ == "__main__":
    root = tk.Tk()
    root.title("LockScript")
    root.geometry("400x200")
    root.update()
    app = LockScript(root)
    root.mainloop()
