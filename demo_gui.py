#!/usr/bin/env python3
"""
Demo script showing GUI features.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def show_gui_preview():
    """Show a preview of the GUI without running full app."""
    root = tk.Tk()
    root.title("Secure File Encryptor GUI Preview")
    root.geometry("600x400")
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Create preview content
    main_frame = ttk.Frame(root, padding="30")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    title = ttk.Label(
        main_frame,
        text="🔒 Secure File Encryptor GUI",
        font=('Arial', 20, 'bold'),
        foreground='#2c3e50'
    )
    title.pack(pady=(0, 20))
    
    features = [
        "✓ User-friendly graphical interface",
        "✓ File encryption/decryption with AES-256-GCM",
        "✓ Drag-and-drop file selection",
        "✓ Password strength indicators",
        "✓ File information viewer",
        "✓ Progress indicators",
        "✓ Dark/Light theme support"
    ]
    
    for feature in features:
        label = ttk.Label(main_frame, text=feature, font=('Arial', 12))
        label.pack(anchor=tk.W, pady=5)
    
    ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=20)
    
    button_frame = ttk.Frame(main_frame)
    button_frame.pack()
    
    def launch_gui():
        root.destroy()
        try:
            from src.sfe.gui import main
            main()
        except ImportError as e:
            messagebox.showerror("Error", f"Cannot launch GUI: {e}")
    
    ttk.Button(
        button_frame,
        text="Launch Full GUI",
        command=launch_gui,
        width=20
    ).pack(side=tk.LEFT, padx=5)
    
    ttk.Button(
        button_frame,
        text="Close Preview",
        command=root.destroy,
        width=20
    ).pack(side=tk.LEFT, padx=5)
    
    root.mainloop()

if __name__ == "__main__":
    show_gui_preview()