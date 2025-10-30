# Author: Mohammed Nuzair Sharieff 
# Project: Advanced OS - Antivirus Scanner
import customtkinter as ctk
# ... rest of the codeimport customtkinter as ctk
import os
import threading
import time
import json
from tkinter import filedialog, messagebox
from PIL import Image

# --- MOCK VIRUS SIGNATURES ---
# Fixed: Used a raw string (r"...") to prevent SyntaxWarning
VIRUS_SIGNATURES = {
    "TestVirus_1": r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "DummyMalware.txt": "this is a harmless dummy malware file",
    "SimpleTrojan.js": "window.location.href = 'http://malicious.com'"
}

class ThreatScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Window Configuration ---
        self.title("Threat Scanner Pro")
        self.geometry("900x650")

        # --- Load Settings and Icons ---
        self.load_settings()
        self.load_icons()

        # --- State Variables ---
        self.scan_in_progress = False
        self.directory_to_scan = ""

        # --- Main Layout (Sidebar + Content Area) ---
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        # --- Content Frames ---
        self.scan_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.settings_frame = ctk.CTkFrame(self, fg_color="transparent")

        # --- UI Initialization ---
        self.create_sidebar_widgets()
        self.create_scan_widgets()
        self.create_settings_widgets()

        # Show the default frame
        self.select_frame_by_name("scan")

    def load_icons(self):
        """
        --- CODE REVERTED ---
        Loads .PNG icons directly using Pillow.
        """
        try:
            # --- ICON FILENAMES UPDATED TO .PNG ---
            self.scan_icon = ctk.CTkImage(Image.open("icons/qrcode-solid-full.png"), size=(24, 24))
            self.shield_icon = ctk.CTkImage(Image.open("icons/shield-halved-solid-full.png"), size=(24, 24))
            self.settings_icon = ctk.CTkImage(Image.open("icons/gear-solid-full.png"), size=(24, 24))
            # ------------------------------------
        except FileNotFoundError as e:
            print(f"Icon loading error: {e}")
            print("Please make sure your 'icons' folder exists and contains the .png files.")
            messagebox.showerror("Icon Error", "Could not find icon files. Make sure the 'icons' folder with PNG files exists.")
            # Handle this error, maybe close the app or continue without icons
            self.scan_icon = None
            self.shield_icon = None
            self.settings_icon = None
        except Exception as e:
            print(f"An unexpected error occurred while loading icons: {e}")
            
    # ... (the rest of the code is exactly the same) ...

    def create_sidebar_widgets(self):
        """Creates the navigation buttons on the sidebar."""
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Scanner Pro", image=self.shield_icon, compound="left", font=ctk.CTkFont(size=18, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=20)

        self.scan_button_nav = ctk.CTkButton(self.sidebar_frame, text="Scanner", image=self.scan_icon, compound="left", command=lambda: self.select_frame_by_name("scan"))
        self.scan_button_nav.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.settings_button_nav = ctk.CTkButton(self.sidebar_frame, text="Settings", image=self.settings_icon, compound="left", command=lambda: self.select_frame_by_name("settings"))
        self.settings_button_nav.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 20))
        self.appearance_mode_optionemenu.set(self.settings.get("theme", "Dark"))


    def select_frame_by_name(self, name):
        """Shows the selected frame and hides the others."""
        # Set button colors
        self.scan_button_nav.configure(fg_color=("gray75", "gray25") if name == "scan" else "transparent")
        self.settings_button_nav.configure(fg_color=("gray75", "gray25") if name == "settings" else "transparent")

        # Show the selected frame
        if name == "scan":
            self.scan_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        else:
            self.scan_frame.grid_forget()
        if name == "settings":
            self.settings_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        else:
            self.settings_frame.grid_forget()

    def create_scan_widgets(self):
        """Creates all the widgets for the main scanning interface."""
        # --- Header ---
        self.header_label = ctk.CTkLabel(self.scan_frame, text="System Threat Scan", font=ctk.CTkFont(size=30, weight="bold"))
        self.header_label.pack(pady=(0, 20))

        # --- Directory Selection Frame ---
        self.dir_frame = ctk.CTkFrame(self.scan_frame)
        self.dir_frame.pack(pady=10, padx=0, fill="x")

        self.select_dir_button = ctk.CTkButton(self.dir_frame, text="Select Directory", command=self.select_directory)
        self.select_dir_button.pack(side="left", padx=(0, 10))

        self.dir_path_label = ctk.CTkLabel(self.dir_frame, text="No directory selected...", text_color="gray", anchor="w")
        self.dir_path_label.pack(side="left", fill="x", expand=True)

        # --- Scan Button ---
        self.scan_button = ctk.CTkButton(self.scan_frame, text="Start Scan", command=self.start_scan_thread, height=40, font=ctk.CTkFont(size=16, weight="bold"))
        self.scan_button.pack(pady=20, padx=0, fill="x")

        # --- Progress & Status ---
        self.progress_bar = ctk.CTkProgressBar(self.scan_frame)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=10, padx=0, fill="x")

        self.status_label = ctk.CTkLabel(self.scan_frame, text="Status: Ready", anchor="w")
        self.status_label.pack(pady=(5, 0), padx=0, fill="x")
        
        self.current_file_label = ctk.CTkLabel(self.scan_frame, text="", text_color="gray", anchor="w", wraplength=700)
        self.current_file_label.pack(pady=(0, 10), padx=0, fill="x")

        # --- Results Display ---
        self.results_frame = ctk.CTkScrollableFrame(self.scan_frame, label_text="Scan Results")
        self.results_frame.pack(pady=10, padx=0, fill="both", expand=True)
        self.results_label_welcome = ctk.CTkLabel(self.results_frame, text="Scan results will appear here.")
        self.results_label_welcome.pack()

    def create_settings_widgets(self):
        """Creates widgets for the settings panel."""
        self.settings_label = ctk.CTkLabel(self.settings_frame, text="Application Settings", font=ctk.CTkFont(size=30, weight="bold"))
        self.settings_label.pack(pady=(0, 20), anchor="w")
        
        self.info_label = ctk.CTkLabel(self.settings_frame, text="More settings like managing exclusions, \nupdating virus definitions, or scheduling scans \ncan be added here in the future.",
                                       font=ctk.CTkFont(size=14))
        self.info_label.pack(pady=10, anchor="w")


    def select_directory(self):
        path = filedialog.askdirectory(title="Select a Folder to Scan")
        if path:
            self.directory_to_scan = path
            display_path = path if len(path) < 70 else "..." + path[-67:]
            self.dir_path_label.configure(text=display_path, text_color=("black", "white"))
            self.status_label.configure(text="Status: Ready to scan")
            self.progress_bar.set(0)

    def start_scan_thread(self):
        if not self.directory_to_scan:
            messagebox.showwarning("Warning", "Please select a directory first.")
            return
        if self.scan_in_progress:
            messagebox.showinfo("Info", "A scan is already in progress.")
            return
            
        self.scan_in_progress = True
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.select_dir_button.configure(state="disabled")
        self.progress_bar.set(0)
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        self.scan_thread = threading.Thread(target=self.scan_directory, args=(self.directory_to_scan,))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def scan_directory(self, directory):
        threats_found = 0
        all_files = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]
        total_files = len(all_files) if all_files else 1

        for i, filepath in enumerate(all_files):
            self.after(0, lambda p=filepath: self.current_file_label.configure(text=f"Scanning: {os.path.basename(p)}"))
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
                    for virus_name, signature in VIRUS_SIGNATURES.items():
                        if signature in content:
                            threats_found += 1
                            self.after(0, self.add_result_entry, f"THREAT: {virus_name}", filepath, "red")
                            break
            except Exception:
                pass
            progress = (i + 1) / total_files
            self.after(0, self.progress_bar.set, progress)
            time.sleep(0.01)

        self.after(0, self.finalize_scan, len(all_files), threats_found)

    def add_result_entry(self, name, path, color):
        entry_frame = ctk.CTkFrame(self.results_frame)
        entry_frame.pack(fill="x", padx=5, pady=5)

        path_text = path if len(path) < 60 else f"...{path[-57:]}"
        details_label = ctk.CTkLabel(entry_frame, text=f"{name} at {path_text}", text_color=color, anchor="w")
        details_label.pack(side="left", fill="x", expand=True, padx=10)

        quarantine_button = ctk.CTkButton(entry_frame, text="Quarantine", command=lambda p=path, b=entry_frame: self.quarantine_file(p, b))
        quarantine_button.pack(side="right", padx=10)

    def quarantine_file(self, file_path, button_frame):
        """Moves a file to the quarantine directory."""
        quarantine_dir = "quarantine"
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        
        try:
            file_name = os.path.basename(file_path)
            new_path = os.path.join(quarantine_dir, file_name)
            
            count = 1
            while os.path.exists(new_path):
                name, ext = os.path.splitext(file_name)
                new_path = os.path.join(quarantine_dir, f"{name}_{count}{ext}")
                count += 1

            os.rename(file_path, new_path)
            messagebox.showinfo("Success", f"File '{file_name}' was moved to quarantine.")
            
            for widget in button_frame.winfo_children():
                widget.configure(state="disabled")
            button_frame.configure(fg_color="gray20")

        except Exception as e:
            messagebox.showerror("Error", f"Could not quarantine file: {e}")

    def finalize_scan(self, files_scanned, threats_found):
        self.scan_in_progress = False
        self.scan_button.configure(state="normal", text="Start Scan")
        self.select_dir_button.configure(state="normal")
        self.current_file_label.configure(text="")

        if threats_found > 0:
            status_text = f"Status: Complete. Found {threats_found} threat(s) in {files_scanned} files."
            self.status_label.configure(text=status_text, text_color="#FF4500") # OrangeRed
        else:
            status_text = f"Status: Complete. No threats found in {files_scanned} files."
            self.status_label.configure(text=status_text, text_color="#228B22") # ForestGreen
            no_threat_label = ctk.CTkLabel(self.results_frame, text="System is clean. No threats detected.")
            no_threat_label.pack()

    def load_settings(self):
        """Loads settings from a JSON file."""
        try:
            with open("settings.json", "r") as f:
                self.settings = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.settings = {"theme": "Dark"} # Default settings
        ctk.set_appearance_mode(self.settings.get("theme", "Dark"))

    def save_settings(self):
        """Saves current settings to a JSON file."""
        with open("settings.json", "w") as f:
            json.dump(self.settings, f, indent=4)

    def change_appearance_mode_event(self, new_appearance_mode: str):
        """Changes theme and saves the setting."""
        ctk.set_appearance_mode(new_appearance_mode)
        self.settings["theme"] = new_appearance_mode
        self.save_settings()


if __name__ == "__main__":
    app = ThreatScannerApp()
    app.mainloop()