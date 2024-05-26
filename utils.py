import pandas as pd
from tkinter import filedialog, messagebox

def load_file(filepath):
    try:
        df = pd.read_csv(filepath)
        return df
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while loading the file: {e}")
        return None

def save_file(data, title):
    save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title=title)
    if save_path:
        try:
            if isinstance(data, pd.DataFrame):
                data.to_csv(save_path, index=False)
            else:
                pd.DataFrame(data).to_csv(save_path, index=False)
            messagebox.showinfo("Success", f"File saved successfully as {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the file: {e}")
