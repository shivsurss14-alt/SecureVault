"""
SecureVault - Encrypted Password Manager  (Python + MySQL + Tkinter)

Screen flow:
  1. Password screen   (logo background, 3 wrong attempts -> program exits)
  2. Welcome screen    ("Welcome" button)
  3. Info screen       (purpose, uses, advantages, conditions, "I Agree" button)
  4. Loading screen    (progress bar)
  5. Final screen      ("WELCOME TO SecureVault", "Start" button)
  6. Main dashboard    (encrypted password vault)

Setup:
    pip install mysql-connector-python cryptography pillow
    Keep the "screens" folder (background images) next to this file.
    Change DB_CONFIG below (user / password), then run:  python securevault_app.py

Security design:
  * Master password is never stored. A key is derived from it with PBKDF2-HMAC-SHA256 (200k rounds + random salt).
  * Only a hash of that key is stored (to verify login).
  * Every saved password is encrypted with Fernet (AES-128-CBC + HMAC) before it goes to MySQL.
  * Auto-lock after inactivity, clipboard auto-clear, exit after 3 wrong attempts.
"""
import base64
import hashlib
import hmac
import os
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import mysql.connector
    from cryptography.fernet import Fernet, InvalidToken
    from PIL import Image, ImageTk
except ImportError as e:
    print("Missing package:", e)
    print("Run:  pip install mysql-connector-python cryptography pillow")
    raise SystemExit(1)

DB_CONFIG = {"host": "localhost", "user": "root", "password": "your_password"}
DB_NAME = "securevault_db"
LOCK_SECONDS = 120        # auto-lock after this many idle seconds (dashboard only)
CLIPBOARD_SECONDS = 15    # clear clipboard after copying a password
MAX_ATTEMPTS = 3          # wrong password attempts before the program exits

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENS_DIR = os.path.join(BASE_DIR, "screens")
WIN_W, WIN_H = 1000, 650
NAVY, TEAL, WHITE, FIELD = "#0B1220", "#22D3EE", "#F1F5F9", "#16213A"


# ---------------------------- Database layer ----------------------------
def get_conn():
    return mysql.connector.connect(database=DB_NAME, **DB_CONFIG)


def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    cur.execute(f"USE {DB_NAME}")
    cur.execute("""CREATE TABLE IF NOT EXISTS vault_meta (
                       id INT PRIMARY KEY,
                       salt VARBINARY(16) NOT NULL,
                       verifier CHAR(64) NOT NULL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS entries (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       site VARCHAR(100) NOT NULL,
                       username VARCHAR(100),
                       password_enc TEXT NOT NULL,
                       notes VARCHAR(255),
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    conn.close()


def run(query, params=(), fetch=False):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall() if fetch else None
    conn.commit()
    conn.close()
    return rows


# ------------------------------ Crypto helpers ------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)


def verifier_of(key: bytes) -> str:
    return hashlib.sha256(b"verify" + key).hexdigest()


def strength(pw: str):
    score = min(len(pw), 16) * 4
    for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation):
        if any(c in group for c in pw):
            score += 9
    score = min(score, 100)
    label = "Weak" if score < 40 else "Medium" if score < 70 else "Strong"
    return score, label


def generate_password(length=16):
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+"]
    chars = "".join(pools)
    while True:
        pw = "".join(secrets.choice(chars) for _ in range(length))
        if all(any(c in p for c in pw) for p in pools):
            return pw


# ------------------------------- Intro screens -------------------------------
class BgScreen(tk.Canvas):
    """A full-window canvas with a background image; buttons/entries are placed on top."""

    def __init__(self, app, image_name):
        super().__init__(app, width=WIN_W, height=WIN_H, highlightthickness=0, bg=NAVY)
        self.app = app
        self.photo = None
        try:
            self.photo = ImageTk.PhotoImage(Image.open(os.path.join(SCREENS_DIR, image_name)))
            self.create_image(0, 0, image=self.photo, anchor="nw")
        except (OSError, FileNotFoundError):
            self.create_text(WIN_W // 2, 140, text="SecureVault", fill=WHITE, font=("Arial", 44, "bold"))
            self.create_text(WIN_W // 2, 200, text=f"(background image missing: screens/{image_name})",
                             fill="#94A3B8", font=("Arial", 12))

    def button(self, text, y, command, width=16):
        b = tk.Button(self, text=text, command=command, width=width, font=("Arial", 13, "bold"),
                      bg=TEAL, fg=NAVY, activebackground="#67E8F9", activeforeground=NAVY,
                      relief="flat", cursor="hand2", pady=6)
        self.create_window(WIN_W // 2, y, window=b)
        return b

    def entry(self, y, var):
        e = tk.Entry(self, textvariable=var, show="*", width=26, font=("Arial", 14), justify="center",
                     bg=FIELD, fg=WHITE, insertbackground=WHITE, relief="flat",
                     highlightthickness=2, highlightbackground="#334155", highlightcolor=TEAL)
        self.create_window(WIN_W // 2, y, window=e, height=38)
        return e


class PasswordScreen(BgScreen):
    """Step 1: master password. 3 wrong attempts close the program."""

    def __init__(self, app):
        super().__init__(app, "1_password_bg.png")
        meta = run("SELECT salt, verifier FROM vault_meta WHERE id=1", fetch=True)
        self.meta = meta[0] if meta else None
        self.attempts = 0
        self.pw, self.pw2 = tk.StringVar(), tk.StringVar()
        self.status = None
        if self.meta:
            self.e1 = self.entry(480, self.pw)
            self.button("Submit", 548, self.submit)
            self.status = self.create_text(WIN_W // 2, 600, text="", fill="#F87171", font=("Arial", 12, "bold"))
        else:
            self.create_text(WIN_W // 2, 466, fill=TEAL, font=("Arial", 11),
                             text="First run: create your master password (min 8 characters) and confirm it")
            self.e1 = self.entry(498, self.pw)
            e2 = self.entry(540, self.pw2)
            e2.bind("<Return>", lambda ev: self.submit())
            self.button("Create & Submit", 590, self.submit)
        self.e1.bind("<Return>", lambda ev: self.submit())
        self.e1.focus_set()

    def submit(self):
        pw = self.pw.get()
        if self.meta is None:
            if len(pw) < 8:
                return messagebox.showerror("Weak password", "Master password must be at least 8 characters.")
            if pw != self.pw2.get():
                return messagebox.showerror("Mismatch", "Both passwords must match.")
            salt = os.urandom(16)
            key = derive_key(pw, salt)
            run("INSERT INTO vault_meta (id, salt, verifier) VALUES (1, %s, %s)", (salt, verifier_of(key)))
            self.app.login_ok(key)
            return
        key = derive_key(pw, bytes(self.meta[0]))
        if hmac.compare_digest(verifier_of(key), self.meta[1]):
            self.app.login_ok(key)
            return
        self.attempts += 1
        self.pw.set("")
        left = MAX_ATTEMPTS - self.attempts
        if left <= 0:
            messagebox.showerror("Access denied", f"Incorrect password {MAX_ATTEMPTS} times.\nThe program will now exit.")
            self.app.destroy()
        else:
            self.itemconfig(self.status, text=f"Attempts left: {left}")
            messagebox.showerror("Incorrect password", f"Incorrect password. Try again.\nAttempts left: {left}")


class WelcomeScreen(BgScreen):
    """Step 2: welcome screen with the Welcome button."""

    def __init__(self, app):
        super().__init__(app, "2_welcome_bg.png")
        self.button("Welcome", 545, app.show_info)


class InfoScreen(BgScreen):
    """Step 3: uses, purpose, advantages, conditions + I Agree button."""

    def __init__(self, app):
        super().__init__(app, "3_info_bg.png")
        self.button("I Agree", 600, app.show_loading)


class LoadingScreen(BgScreen):
    """Step 4: animated loading bar (about 3.5 seconds)."""

    def __init__(self, app):
        super().__init__(app, "4_loading_bg.png")
        style = ttk.Style()
        style.configure("Vault.Horizontal.TProgressbar", troughcolor=FIELD, background=TEAL,
                        bordercolor="#334155", lightcolor=TEAL, darkcolor=TEAL)
        self.bar = ttk.Progressbar(self, style="Vault.Horizontal.TProgressbar", length=520,
                                   maximum=100, mode="determinate")
        self.create_window(WIN_W // 2, 500, window=self.bar, height=20)
        self.pct = self.create_text(WIN_W // 2, 540, text="0%", fill=TEAL, font=("Arial", 14, "bold"))
        self.value = 0
        self.step()

    def step(self):
        self.value += 1
        self.bar["value"] = self.value
        self.itemconfig(self.pct, text=f"{self.value}%")
        if self.value >= 100:
            self.after(300, self.app.show_final)
        else:
            self.after(35, self.step)


class FinalScreen(BgScreen):
    """Step 5: WELCOME TO SecureVault + Start button -> dashboard."""

    def __init__(self, app):
        super().__init__(app, "5_final_bg.png")
        self.button("Start", 580, app.show_dashboard)


# ------------------------------- Main dashboard -------------------------------
class VaultFrame(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.sel = None
        self.v_site, self.v_user = tk.StringVar(), tk.StringVar()
        self.v_pw, self.v_notes = tk.StringVar(), tk.StringVar()
        self.v_search = tk.StringVar()
        self.show_pw = tk.BooleanVar(value=False)
        self.build_form()
        self.build_table()
        self.v_pw.trace_add("write", self.update_strength)
        self.v_search.trace_add("write", lambda *a: self.refresh())
        self.refresh()

    def build_form(self):
        f = ttk.LabelFrame(self, text="Entry")
        f.pack(fill="x", padx=10, pady=8)
        ttk.Label(f, text="Site / App").grid(row=0, column=0, padx=5, pady=4, sticky="e")
        ttk.Entry(f, textvariable=self.v_site, width=28).grid(row=0, column=1)
        ttk.Label(f, text="Username / Email").grid(row=0, column=2, padx=5, sticky="e")
        ttk.Entry(f, textvariable=self.v_user, width=28).grid(row=0, column=3)

        ttk.Label(f, text="Password").grid(row=1, column=0, padx=5, pady=4, sticky="e")
        self.pw_entry = ttk.Entry(f, textvariable=self.v_pw, show="*", width=28)
        self.pw_entry.grid(row=1, column=1)
        ttk.Checkbutton(f, text="Show", variable=self.show_pw, command=self.toggle_show).grid(row=1, column=2)
        ttk.Button(f, text="Generate", command=lambda: self.v_pw.set(generate_password())).grid(row=1, column=3, sticky="w")

        ttk.Label(f, text="Strength").grid(row=2, column=0, padx=5, sticky="e")
        self.bar = ttk.Progressbar(f, length=200, maximum=100)
        self.bar.grid(row=2, column=1, sticky="w")
        self.lbl_strength = ttk.Label(f, text="")
        self.lbl_strength.grid(row=2, column=2, sticky="w")

        ttk.Label(f, text="Notes").grid(row=3, column=0, padx=5, pady=4, sticky="e")
        ttk.Entry(f, textvariable=self.v_notes, width=62).grid(row=3, column=1, columnspan=3, sticky="w")

        b = ttk.Frame(f)
        b.grid(row=4, column=0, columnspan=4, pady=6)
        for text, cmd in (("Add", self.add), ("Update", self.update_row), ("Delete", self.delete),
                          ("Copy Password", self.copy_pw), ("Clear", self.clear_form), ("Lock", self.app.show_login)):
            ttk.Button(b, text=text, command=cmd).pack(side="left", padx=4)

    def build_table(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10)
        ttk.Label(top, text="Search:").pack(side="left")
        ttk.Entry(top, textvariable=self.v_search, width=30).pack(side="left", padx=5)
        cols = ("id", "site", "username", "notes")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=11)
        for c, w in zip(cols, (50, 200, 240, 260)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, padx=10, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

    # ---- helpers ----
    def toggle_show(self):
        self.pw_entry.config(show="" if self.show_pw.get() else "*")

    def update_strength(self, *_):
        score, label = strength(self.v_pw.get())
        self.bar["value"] = score if self.v_pw.get() else 0
        self.lbl_strength.config(text=label if self.v_pw.get() else "")

    def clear_form(self):
        self.sel = None
        for v in (self.v_site, self.v_user, self.v_pw, self.v_notes):
            v.set("")
        self.tree.selection_remove(self.tree.selection())

    def read_form(self):
        site, pw = self.v_site.get().strip(), self.v_pw.get()
        if not site or not pw:
            messagebox.showerror("Missing", "Site and password are required.")
            return None
        enc = self.app.fernet.encrypt(pw.encode()).decode()
        return site, self.v_user.get().strip(), enc, self.v_notes.get().strip()

    # ---- actions ----
    def add(self):
        data = self.read_form()
        if data:
            run("INSERT INTO entries (site, username, password_enc, notes) VALUES (%s,%s,%s,%s)", data)
            self.clear_form()
            self.refresh()

    def update_row(self):
        if self.sel is None:
            return messagebox.showinfo("Select", "Select an entry to update.")
        data = self.read_form()
        if data:
            run("UPDATE entries SET site=%s, username=%s, password_enc=%s, notes=%s WHERE id=%s",
                data + (self.sel,))
            self.clear_form()
            self.refresh()

    def delete(self):
        if self.sel is None:
            return messagebox.showinfo("Select", "Select an entry to delete.")
        if messagebox.askyesno("Confirm", "Delete this entry permanently?"):
            run("DELETE FROM entries WHERE id=%s", (self.sel,))
            self.clear_form()
            self.refresh()

    def copy_pw(self):
        pw = self.v_pw.get()
        if not pw:
            return
        self.app.clipboard_clear()
        self.app.clipboard_append(pw)
        self.app.after(CLIPBOARD_SECONDS * 1000, self.app.clipboard_clear)
        messagebox.showinfo("Copied", f"Password copied. Clipboard clears in {CLIPBOARD_SECONDS} seconds.")

    def on_select(self, _e):
        sel = self.tree.selection()
        if not sel:
            return
        i, site, user, notes = self.tree.item(sel[0])["values"]
        row = run("SELECT password_enc FROM entries WHERE id=%s", (i,), fetch=True)
        try:
            pw = self.app.fernet.decrypt(row[0][0].encode()).decode()
        except InvalidToken:
            return messagebox.showerror("Error", "Could not decrypt this entry.")
        self.sel = i
        self.v_site.set(site)
        self.v_user.set(user)
        self.v_notes.set(notes)
        self.v_pw.set(pw)

    def refresh(self):
        like = f"%{self.v_search.get().strip()}%"
        rows = run("SELECT id, site, username, notes FROM entries "
                   "WHERE site LIKE %s OR username LIKE %s ORDER BY site", (like, like), fetch=True)
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", "end", values=r)


# ------------------------------- App shell -------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureVault - Encrypted Password Manager")
        ttk.Style(self).theme_use("clam")
        self.fernet = None
        self.current = None
        self.lock_job = None
        self.intro_done = False   # after the first full run-through, locking returns only to the password screen
        self.bind_all("<Key>", self.reset_timer)
        self.bind_all("<Button>", self.reset_timer)
        self.show_login()

    def set_size(self, w, h, resizable=False):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = max((self.winfo_screenheight() - h) // 2 - 20, 0)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.resizable(resizable, resizable)

    def swap(self, frame):
        if self.current:
            self.current.destroy()
        self.current = frame
        frame.pack(fill="both", expand=True)

    # ---- navigation ----
    def show_login(self):
        if self.lock_job:
            self.after_cancel(self.lock_job)
            self.lock_job = None
        self.fernet = None
        try:
            self.clipboard_clear()
        except tk.TclError:
            pass
        self.set_size(WIN_W, WIN_H)
        self.swap(PasswordScreen(self))

    def login_ok(self, key):
        self.fernet = Fernet(base64.urlsafe_b64encode(key))
        if self.intro_done:
            self.show_dashboard()
        else:
            self.swap(WelcomeScreen(self))

    def show_info(self):
        self.swap(InfoScreen(self))

    def show_loading(self):
        self.swap(LoadingScreen(self))

    def show_final(self):
        self.swap(FinalScreen(self))

    def show_dashboard(self):
        self.intro_done = True
        self.set_size(820, 600, resizable=True)
        self.swap(VaultFrame(self))
        self.reset_timer()

    def reset_timer(self, _e=None):
        if self.fernet is None or not isinstance(self.current, VaultFrame):
            return
        if self.lock_job:
            self.after_cancel(self.lock_job)
        self.lock_job = self.after(LOCK_SECONDS * 1000, self.show_login)


if __name__ == "__main__":
    try:
        init_db()
    except mysql.connector.Error as e:
        print("MySQL connection failed. Check DB_CONFIG (user/password) and that MySQL is running.\n", e)
        raise SystemExit(1)
    App().mainloop()
