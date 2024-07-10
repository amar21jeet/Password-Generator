import random
import string
import tkinter as tk
from tkinter import messagebox
import pyperclip

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")

        self.password_history = []
        
        # Label and entry for password length
        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.length_entry = tk.Entry(master)
        self.length_entry.grid(row=0, column=1, padx=5, pady=5)

        # Checkboxes for password options
        self.uppercase_var = tk.IntVar()
        self.uppercase_check = tk.Checkbutton(master, text="Uppercase", variable=self.uppercase_var)
        self.uppercase_check.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.lowercase_var = tk.IntVar()
        self.lowercase_check = tk.Checkbutton(master, text="Lowercase", variable=self.lowercase_var)
        self.lowercase_check.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.numbers_var = tk.IntVar()
        self.numbers_check = tk.Checkbutton(master, text="Numbers", variable=self.numbers_var)
        self.numbers_check.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        self.symbols_var = tk.IntVar()
        self.symbols_check = tk.Checkbutton(master, text="Symbols", variable=self.symbols_var)
        self.symbols_check.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        # Generate password button
        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=2, columnspan=4, padx=5, pady=5)

        # Password display
        self.password_label = tk.Label(master, text="Generated Password:")
        self.password_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.password_display = tk.Label(master, text="", relief="sunken", padx=5, pady=5, bg="white", anchor="w")
        self.password_display.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="we")

        # Copy to clipboard button
        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=3, column=3, padx=5, pady=5, sticky="e")

        # Password strength meter
        self.strength_label = tk.Label(master, text="Password Strength:")
        self.strength_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.strength_display = tk.Label(master, text="", padx=5, pady=5, bg="white", anchor="w")
        self.strength_display.grid(row=4, column=1, columnspan=3, padx=5, pady=5, sticky="we")

        # Password history
        self.history_label = tk.Label(master, text="Password History:")
        self.history_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.history_display = tk.Text(master, height=5, width=30, padx=5, pady=5)
        self.history_display.grid(row=5, column=1, columnspan=3, padx=5, pady=5, sticky="we")

        # Clear history button
        self.clear_button = tk.Button(master, text="Clear History", command=self.clear_history)
        self.clear_button.grid(row=6, columnspan=4, padx=5, pady=5)

    def generate_password(self):
        length = int(self.length_entry.get())
        options = {
            'uppercase': bool(self.uppercase_var.get()),
            'lowercase': bool(self.lowercase_var.get()),
            'numbers': bool(self.numbers_var.get()),
            'symbols': bool(self.symbols_var.get())
        }

        if not any(options.values()):
            messagebox.showwarning("Warning", "Please select at least one option.")
            return

        password = self.generate_random_password(length, **options)
        self.password_display.config(text=password)

        strength = self.check_password_strength(password)
        self.strength_display.config(text=strength)

        self.password_history.append(password)
        self.update_password_history()

    def generate_random_password(self, length, uppercase=True, lowercase=True, numbers=True, symbols=True):
        characters = ''
        if uppercase:
            characters += string.ascii_uppercase
        if lowercase:
            characters += string.ascii_lowercase
        if numbers:
            characters += string.digits
        if symbols:
            characters += string.punctuation

        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def check_password_strength(self, password):
        # Password length
        length = len(password)

        # Character diversity
        diversity = len(set(password)) / length

        # Presence of patterns or dictionary words (basic check)
        weak_patterns = ['123', 'abc', 'password', 'qwerty', '123456']
        has_weak_pattern = any(pattern in password.lower() for pattern in weak_patterns)

        # Password strength estimation
        if length < 8 or diversity < 0.5 or has_weak_pattern:
            return "Weak"
        elif length < 12 or diversity < 0.7:
            return "Medium"
        else:
            return "Strong"

    def update_password_history(self):
        self.history_display.delete(1.0, tk.END)
        for password in self.password_history:
            self.history_display.insert(tk.END, password + "\n")

    def clear_history(self):
        self.password_history = []
        self.update_password_history()

    def copy_to_clipboard(self):
        password = self.password_display.cget("text")
        pyperclip.copy(password)
        messagebox.showinfo("Info", "Password copied to clipboard.")

def main():
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()









