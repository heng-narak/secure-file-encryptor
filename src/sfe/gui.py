"""
GUI for Secure File Encryptor using Tkinter.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
from pathlib import Path
from typing import Optional

from .core import encrypt_file, decrypt_file, get_file_info
from . import __version__


class SecureFileEncryptorGUI:
    """Main GUI application for the Secure File Encryptor."""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"Secure File Encryptor v{__version__}")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Configure styles
        self.setup_styles()
        
        # Variables
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.operation_mode = tk.StringVar(value="encrypt")
        
        # Build UI
        self.setup_ui()
        
        # Center window
        self.center_window()
        
    def setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')  # Good cross-platform theme
        
        # Configure colors
        self.root.configure(bg='#f0f0f0')
        
    def center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def setup_ui(self):
        """Setup the main UI components."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="🔒 Secure File Encryptor",
            font=('Arial', 24, 'bold'),
            foreground='#2c3e50'
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 30))
        
        # Subtitle
        subtitle_label = ttk.Label(
            main_frame,
            text="AES-256-GCM File Encryption Tool",
            font=('Arial', 12),
            foreground='#7f8c8d'
        )
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 30))
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding="10")
        mode_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
        mode_frame.columnconfigure(0, weight=1)
        mode_frame.columnconfigure(1, weight=1)
        
        ttk.Radiobutton(
            mode_frame,
            text="🔐 Encrypt File",
            variable=self.operation_mode,
            value="encrypt",
            command=self.on_mode_change
        ).grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        ttk.Radiobutton(
            mode_frame,
            text="🔓 Decrypt File",
            variable=self.operation_mode,
            value="decrypt",
            command=self.on_mode_change
        ).grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        ttk.Radiobutton(
            mode_frame,
            text="📄 File Info",
            variable=self.operation_mode,
            value="info",
            command=self.on_mode_change
        ).grid(row=0, column=2, padx=10, pady=5, sticky=tk.W)
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        file_entry = ttk.Entry(file_frame, textvariable=self.input_file, width=50)
        file_entry.grid(row=0, column=1, padx=(10, 5), pady=5, sticky=(tk.W, tk.E))
        
        ttk.Button(
            file_frame,
            text="Browse...",
            command=self.browse_input_file
        ).grid(row=0, column=2, padx=(5, 0), pady=5)
        
        # Output file (only for encrypt/decrypt)
        self.output_label = ttk.Label(file_frame, text="Output File:")
        self.output_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.output_entry = ttk.Entry(file_frame, textvariable=self.output_file, width=50)
        self.output_entry.grid(row=1, column=1, padx=(10, 5), pady=5, sticky=(tk.W, tk.E))
        
        self.output_button = ttk.Button(
            file_frame,
            text="Browse...",
            command=self.browse_output_file
        )
        self.output_button.grid(row=1, column=2, padx=(5, 0), pady=5)
        
        # Password section
        self.password_frame = ttk.LabelFrame(main_frame, text="Security", padding="10")
        self.password_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
        self.password_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.password_entry = ttk.Entry(
            self.password_frame,
            textvariable=self.password,
            show="•",
            width=50
        )
        self.password_entry.grid(row=0, column=1, padx=(10, 5), pady=5, sticky=(tk.W, tk.E))
        
        # Confirm password (for encryption)
        self.confirm_label = ttk.Label(self.password_frame, text="Confirm Password:")
        self.confirm_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.confirm_entry = ttk.Entry(
            self.password_frame,
            textvariable=self.confirm_password,
            show="•",
            width=50
        )
        self.confirm_entry.grid(row=1, column=1, padx=(10, 5), pady=5, sticky=(tk.W, tk.E))
        
        # Show password checkbox
        self.show_pass_check = ttk.Checkbutton(
            self.password_frame,
            text="Show Password",
            variable=self.show_password,
            command=self.toggle_password_visibility
        )
        self.show_pass_check.grid(row=2, column=1, sticky=tk.W, pady=(5, 0))
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=(10, 20))
        
        self.execute_button = ttk.Button(
            button_frame,
            text="🔐 Encrypt File",
            command=self.execute_operation,
            width=20
        )
        self.execute_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Clear All",
            command=self.clear_all,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Exit",
            command=self.root.quit,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        # Status/Output area
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=10,
            wrap=tk.WORD,
            font=('Consolas', 10)
        )
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Initialize UI state
        self.on_mode_change()
        
    def on_mode_change(self):
        """Update UI based on selected mode."""
        mode = self.operation_mode.get()
        
        if mode == "encrypt":
            self.execute_button.config(text="🔐 Encrypt File")
            self.output_label.grid()
            self.output_entry.grid()
            self.output_button.grid()
            self.confirm_label.grid()
            self.confirm_entry.grid()
            self.show_pass_check.grid()
            
        elif mode == "decrypt":
            self.execute_button.config(text="🔓 Decrypt File")
            self.output_label.grid()
            self.output_entry.grid()
            self.output_button.grid()
            self.confirm_label.grid_remove()
            self.confirm_entry.grid_remove()
            self.show_pass_check.grid()
            
        elif mode == "info":
            self.execute_button.config(text="📄 Get File Info")
            self.output_label.grid_remove()
            self.output_entry.grid_remove()
            self.output_button.grid_remove()
            self.confirm_label.grid_remove()
            self.confirm_entry.grid_remove()
            self.show_pass_check.grid_remove()
            self.password_frame.grid_remove()
            
    def browse_input_file(self):
        """Browse for input file."""
        mode = self.operation_mode.get()
        
        if mode == "info":
            filetypes = [("Encrypted files", "*.enc"), ("All files", "*.*")]
        elif mode == "decrypt":
            filetypes = [("Encrypted files", "*.enc"), ("All files", "*.*")]
        else:  # encrypt
            filetypes = [("All files", "*.*")]
        
        filename = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=filetypes
        )
        
        if filename:
            self.input_file.set(filename)
            
            # Auto-suggest output filename
            if mode == "encrypt":
                self.output_file.set(filename + ".enc")
            elif mode == "decrypt":
                # Try to use original filename from header
                try:
                    info = get_file_info(filename)
                    if info.get("original_filename"):
                        self.output_file.set(info["original_filename"])
                except:
                    # Remove .enc extension if present
                    if filename.lower().endswith('.enc'):
                        self.output_file.set(filename[:-4])
                    else:
                        self.output_file.set(filename + ".decrypted")
    
    def browse_output_file(self):
        """Browse for output file."""
        mode = self.operation_mode.get()
        
        if mode == "encrypt":
            defaultext = ".enc"
            filetypes = [("Encrypted files", "*.enc"), ("All files", "*.*")]
        else:  # decrypt
            defaultext = ".txt"
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
        
        filename = filedialog.asksaveasfilename(
            title="Save Output File",
            defaultextension=defaultext,
            filetypes=filetypes
        )
        
        if filename:
            self.output_file.set(filename)
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        show = self.show_password.get()
        if show:
            self.password_entry.config(show="")
            self.confirm_entry.config(show="")
        else:
            self.password_entry.config(show="•")
            self.confirm_entry.config(show="•")
    
    def validate_inputs(self):
        """Validate user inputs."""
        mode = self.operation_mode.get()
        
        # Check input file
        if not self.input_file.get():
            messagebox.showerror("Error", "Please select an input file.")
            return False
        
        if not Path(self.input_file.get()).exists():
            messagebox.showerror("Error", "Input file does not exist.")
            return False
        
        # Check output file for encrypt/decrypt
        if mode in ["encrypt", "decrypt"]:
            if not self.output_file.get():
                messagebox.showerror("Error", "Please specify an output file.")
                return False
            
            # Check if output file already exists
            if Path(self.output_file.get()).exists():
                response = messagebox.askyesno(
                    "Confirm Overwrite",
                    f"File '{self.output_file.get()}' already exists. Overwrite?"
                )
                if not response:
                    return False
        
        # Check password for encrypt/decrypt
        if mode in ["encrypt", "decrypt"]:
            if not self.password.get():
                messagebox.showerror("Error", "Please enter a password.")
                return False
            
            if mode == "encrypt":
                if self.password.get() != self.confirm_password.get():
                    messagebox.showerror("Error", "Passwords do not match.")
                    return False
                
                if len(self.password.get()) < 8:
                    response = messagebox.askyesno(
                        "Weak Password",
                        "Password is less than 8 characters. Continue anyway?"
                    )
                    if not response:
                        return False
        
        return True
    
    def execute_operation(self):
        """Execute the selected operation."""
        if not self.validate_inputs():
            return
        
        # Disable button during operation
        self.execute_button.config(state=tk.DISABLED)
        self.status_var.set("Processing...")
        
        # Run in separate thread to keep UI responsive
        thread = threading.Thread(target=self._execute_operation_thread)
        thread.daemon = True
        thread.start()
    
    def _execute_operation_thread(self):
        """Thread function for executing operations."""
        try:
            mode = self.operation_mode.get()
            self.output_text.delete(1.0, tk.END)
            
            if mode == "encrypt":
                self._encrypt_file()
            elif mode == "decrypt":
                self._decrypt_file()
            elif mode == "info":
                self._get_file_info()
                
        except Exception as e:
            self.root.after(0, self._show_error, str(e))
        finally:
            self.root.after(0, self._operation_complete)
    
    def _encrypt_file(self):
        """Encrypt file operation."""
        input_path = self.input_file.get()
        output_path = self.output_file.get()
        password = self.password.get()
        
        def update_status(message):
            self.root.after(0, self._append_output, message + "\n")
        
        # Redirect print statements to our output
        import sys
        from io import StringIO
        
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Call encryption function
            result = encrypt_file(input_path, password, output_path)
            
            # Get printed output
            output = sys.stdout.getvalue()
            self.root.after(0, self._append_output, output)
            
            # Show success message
            self.root.after(0, self._show_success, 
                          f"File encrypted successfully!\nSaved to: {result}")
            
        finally:
            sys.stdout = old_stdout
    
    def _decrypt_file(self):
        """Decrypt file operation."""
        input_path = self.input_file.get()
        output_path = self.output_file.get()
        password = self.password.get()
        
        # Redirect print statements
        import sys
        from io import StringIO
        
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Call decryption function
            result = decrypt_file(input_path, password, output_path)
            
            # Get printed output
            output = sys.stdout.getvalue()
            self.root.after(0, self._append_output, output)
            
            # Show success message
            self.root.after(0, self._show_success,
                          f"File decrypted successfully!\nSaved to: {result}")
            
        finally:
            sys.stdout = old_stdout
    
    def _get_file_info(self):
        """Get file information."""
        input_path = self.input_file.get()
        
        try:
            info = get_file_info(input_path)
            
            if "error" in info:
                self.root.after(0, self._show_error, info["error"])
                return
            
            # Format and display info
            output_lines = [
                "=" * 50,
                f"File Information: {input_path}",
                "=" * 50,
                f"Valid encrypted file: {'Yes' if info['is_valid'] else 'No'}",
                f"Version: {info['version']}",
                f"Original filename: {info['original_filename'] or 'Unknown'}",
                "",
                "Sizes:",
                f"  Header: {info['header_size']:,} bytes",
                f"  Ciphertext: {info['ciphertext_size']:,} bytes",
                f"  Total: {info['file_size']:,} bytes",
                "",
                "Cryptographic parameters:",
                f"  Salt: {info['salt_length']} bytes ({info['salt_hex']})",
                f"  Nonce: {info['nonce_length']} bytes ({info['nonce_hex']})",
                f"  Auth Tag: {info['tag_length']} bytes ({info['tag_hex']})",
                "=" * 50
            ]
            
            output = "\n".join(output_lines)
            self.root.after(0, self._append_output, output)
            self.root.after(0, self.status_var.set, "File information retrieved")
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Error getting file info: {e}")
    
    def _append_output(self, text):
        """Append text to output area."""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
    
    def _show_success(self, message):
        """Show success message."""
        messagebox.showinfo("Success", message)
        self.status_var.set("Operation completed successfully")
    
    def _show_error(self, error_message):
        """Show error message."""
        messagebox.showerror("Error", error_message)
        self.status_var.set(f"Error: {error_message[:50]}...")
    
    def _operation_complete(self):
        """Called when operation completes."""
        self.execute_button.config(state=tk.NORMAL)
    
    def clear_all(self):
        """Clear all input fields."""
        self.input_file.set("")
        self.output_file.set("")
        self.password.set("")
        self.confirm_password.set("")
        self.output_text.delete(1.0, tk.END)
        self.status_var.set("Ready")


def main():
    """Launch the GUI application."""
    root = tk.Tk()
    app = SecureFileEncryptorGUI(root)
    
    # Handle window closing
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()