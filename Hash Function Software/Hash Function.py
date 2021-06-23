import hashlib

class Hashing:
    def __init__(self):
        return

    def md5(self, original):
        hashed = hashlib.md5(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha1(self, original):
        hashed = hashlib.sha1(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha224(self, original):
        hashed = hashlib.sha224(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha256(self, original):
        hashed = hashlib.sha256(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha384(self, original):
        hashed = hashlib.sha384(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha512(self, original):
        hashed = hashlib.sha512(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha3_384(self, original):
        hashed = hashlib.sha3_384(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha3_256(self, original):
        hashed = hashlib.sha3_256(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def sha3_224(self, original):
        hashed = hashlib.sha3_224(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def shake_128(self, original):
        hashed = hashlib.shake_128(bytes(original, "utf-8"))
        return hashed.hexdigest(255)

    def shake_256(self, original):
        hashed = hashlib.shake_256(bytes(original, "utf-8"))
        return hashed.hexdigest(255)

    def blake2b(self, original):
        hashed = hashlib.blake2b(bytes(original, "utf-8"))
        return hashed.hexdigest()

    def blake2s(self, original):
        hashed = hashlib.blake2s(bytes(original, "utf-8"))
        return hashed.hexdigest()


import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox as msg


class GUI:
    def __init__(self):
        self.master = Tk()
        self.master.title("Hash Function Software")
        self.master.geometry("500x500")
        self.UI()

    def hash_button_handler(self):
        if self.listbox.get(ANCHOR) == "md5":
            self.hashed = Hashing.md5(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha1":
            self.hashed = Hashing.sha1(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha224":
            self.hashed = Hashing.sha224(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha256":
            self.hashed = Hashing.sha256(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha384":
            self.hashed = Hashing.sha384(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha512":
            self.hashed = Hashing.sha512(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha3_384":
            self.hashed = Hashing.sha3_384(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha3_256":
            self.hashed = Hashing.sha3_256(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "sha3_224":
            self.hashed = Hashing.sha3_224(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "shake_128":
            self.hashed = Hashing.shake_128(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "shake_256":
            self.hashed = Hashing.shake_256(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "blake2b":
            self.hashed = Hashing.blake2b(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "blake2s":
            self.hashed = Hashing.blake2s(self, self.original_Var.get())
            self.hashed_text.delete(1.0, END)
            self.hashed_text.insert(END, self.hashed)
        elif self.listbox.get(ANCHOR) == "":
            msg.showerror("Error", "Please Select an Algorithm")

    def copy_button_handler(self):
        self.master.clipboard_clear()
        self.master.clipboard_append(self.hashed_text.get("1.0","end"))

    def UI(self):
        self.labelframe = tk.LabelFrame(self.master)
        self.labelframe.pack(fill="both", expand="yes")

        og_label = tk.Label(self.labelframe, text="Original")
        og_label.place(x=5, y=0)

        # original text entry
        self.original_Var = tk.StringVar()
        self.original_Entry = tk.Entry(self.labelframe, width=50, textvariable=self.original_Var)
        self.original_Entry.place(x=5, y=20, width=485, height=100)

        # algorithms
        algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_384", "sha3_256",
                      "sha3_224", "shake_128", "shake_256", "blake2b", "blake2s"]

        algorithms_label = tk.Label(self.labelframe, text="Algorithms")
        algorithms_label.place(x=5, y=120)

        scrollbar = tk.Scrollbar(self.labelframe)
        scrollbar.place(x=130, y=130)

        self.listbox = tk.Listbox(self.labelframe, yscrollcommand=scrollbar.set)
        for algo in algorithms:
            self.listbox.insert(END, algo)
        self.listbox.place(x=5, y=140)
        scrollbar.config(command=self.listbox.yview)

        self.hash_button = tk.Button(self.labelframe, text="Hash", command=self.hash_button_handler)
        self.hash_button.place(x=200, y=215)

        hashed_label = tk.Label(self.labelframe, text="Hashed version")
        hashed_label.place(x=5, y=315)

        self.hashed_text = tk.Text(self.labelframe)
        self.hashed_text.place(x=5, y=335, width=485, height=100)

        copy = tk.Button(self.labelframe, text="Copy to Clipboard", command=self.copy_button_handler)
        copy.place(x=5, y=465)


GUI = GUI()
GUI.master.mainloop()
