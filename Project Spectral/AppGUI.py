import customtkinter as ctk
import GUIBackend as backend

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class ProjectSpectralApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Project Spectral")
        self.geometry("1200x700")
        self.minsize(1000, 600)

        # ============= STYLES =============
        self.configure(fg_color="#121212")  # Dark background
        accent_color = "#00BF7A"  # Green accent
        self.font_title = ("Helvetica", 20, "bold")
        self.font_normal = ("Helvetica", 14)
        self.font_small = ("Helvetica", 12)
        self.font_terminal = ("Courier New", 12)

        # ============= TOP TITLE BAR ============
        top_frame = ctk.CTkFrame(self, fg_color="#1f1f1f")
        top_frame.pack(side="top", fill="x")

        title_label = ctk.CTkLabel(top_frame, text="Project Spectral", font=self.font_title, text_color="white")
        title_label.pack(pady=10)

        # ============= MAIN CONTENT AREA =============
        main_frame = ctk.CTkFrame(self, fg_color="#121212")
        main_frame.pack(fill="both", expand=True, padx=10, pady=(5,10))

        # Two panes: Left (Chat) and Right (Terminal)
        chat_frame = ctk.CTkFrame(main_frame, fg_color="#1f1f1f")
        terminal_frame = ctk.CTkFrame(main_frame, fg_color="#1f1f1f")

        chat_frame.pack(side="left", fill="both", expand=True, padx=(0,5))
        terminal_frame.pack(side="right", fill="both", expand=True, padx=(5,0))

        # ============= LEFT PANE (CHAT INTERFACE) =============
        chat_display_frame = ctk.CTkFrame(chat_frame, fg_color="#1f1f1f")
        chat_display_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.chat_textbox = ctk.CTkTextbox(chat_display_frame,
                                           wrap="word",
                                           font=self.font_normal,
                                           text_color="white",
                                           fg_color="#2a2a2a",
                                           state="normal")
        self.chat_textbox.pack(fill="both", expand=True)
        self.chat_textbox.insert("end", "Welcome to Project Spectral.\nEnter a question here ...\n")

        # Bottom portion: user input 
        chat_input_frame = ctk.CTkFrame(chat_frame, fg_color="#1f1f1f")
        chat_input_frame.pack(fill="x", padx=10, pady=(0,10))

        self.user_input = ctk.CTkEntry(chat_input_frame, placeholder_text="Type your message here...",
                                       fg_color="#2a2a2a", text_color="white",
                                       font=self.font_normal)
        self.user_input.pack(side="left", fill="x", expand=True, padx=(0,10), pady=5)

        send_button = ctk.CTkButton(chat_input_frame, text="Send", 
                                    fg_color=accent_color, hover_color="#00A06C", 
                                    text_color="white",
                                    command=self.mock_send_message)
        send_button.pack(side="right")

        # ============= RIGHT PANE (TERMINAL INTERFACE) =============
        terminal_display_frame = ctk.CTkFrame(terminal_frame, fg_color="#1f1f1f")
        terminal_display_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Terminal-like textbox.
        self.terminal_textbox = ctk.CTkTextbox(terminal_display_frame, 
                                               wrap="word",
                                               font=self.font_terminal,
                                               text_color="green",
                                               fg_color="#2a2a2a")
        self.terminal_textbox.pack(fill="both", expand=True)
        self.terminal_textbox.insert("end", "Welcome to the Spectral Terminal\n")

        # Add input and send button for terminal commands
        terminal_input_frame = ctk.CTkFrame(terminal_frame, fg_color="#1f1f1f")
        terminal_input_frame.pack(fill="x", padx=10, pady=(0,10))

        self.terminal_input = ctk.CTkEntry(terminal_input_frame,
                                           placeholder_text="Enter a command...",
                                           fg_color="#2a2a2a",
                                           text_color="white",
                                           font=self.font_normal)
        self.terminal_input.pack(side="left", fill="x", expand=True, padx=(0,10), pady=5)

        terminal_send_button = ctk.CTkButton(terminal_input_frame, text="Run",
                                             fg_color=accent_color, hover_color="#00A06C",
                                             text_color="white",
                                             command=self.run_terminal_command)
        terminal_send_button.pack(side="right")

    def mock_send_message(self):
        user_msg = self.user_input.get()
        if user_msg.strip():
            self.chat_textbox.insert("end", f"User: {user_msg}\nAI: ...\n")
            self.user_input.delete(0, "end")

    def run_terminal_command(self):
        command = self.terminal_input.get().strip()
        shebang = f"$ {backend.run_command("whoami")} >".strip()
        
        if command:
            output = backend.run_command(command)
            
            # Insert the command and its output into the terminal textbox
            self.terminal_textbox.insert("end", f"{shebang} {command}\n")
            self.terminal_textbox.insert("end", f"{output}\n")
            self.terminal_input.delete(0, "end")

if __name__ == "__main__":
    app = ProjectSpectralApp()
    app.mainloop()
