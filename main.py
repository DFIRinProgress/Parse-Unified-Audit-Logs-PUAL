import ttkbootstrap as tb
from ui import AuditLogParserApp

def main():
    root = tb.Window(themename="flatly")
    app = AuditLogParserApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))
    root.mainloop()

def on_closing(root):
    root.quit()

if __name__ == "__main__":
    main()
