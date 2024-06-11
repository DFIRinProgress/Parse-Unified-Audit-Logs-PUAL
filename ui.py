import os
import json
import tkinter as tk
from tkinter import filedialog, messagebox

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from ttkbootstrap import ttk

from data_processing import DataProcessor
from ip_enrichment import IPEnrichment
from visualization import Visualization
from utils import save_file


class AuditLogParserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Parse Unified Audit Logs (PUAL)")
        self.root.geometry("1200x800")
        self.style = ttk.Style()
        self.style.theme_use("flatly")
        self.root.iconbitmap("icon.ico")

        self.filepath = ""
        self.data_processor = DataProcessor()
        self.ip_enrichment = IPEnrichment()
        self.visualization = Visualization()

        self.df = None
        self.ip_list = []
        self.enriched_ip_info = {}
        self.current_visualization_index = 0
        self.visualizations = []
        self.suspicious_operations = self.load_suspicious_operations()

        self.create_widgets()
    
    def load_suspicious_operations(self):
        try:
            with open('config.json', 'r') as file:
                config = json.load(file)
            return config.get("suspicious_operations", [])
        except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
            messagebox.showerror("Error", f"Failed to load suspicious operations from config.json: {e}")
            return []

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=(20, 20))
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # File selection frame
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=0, column=0, sticky="ew", pady=10)
        main_frame.grid_columnconfigure(0, weight=1)

        self.select_file_btn = ttk.Button(file_frame, text="Select CSV File", command=self.select_file, bootstyle="primary")
        self.select_file_btn.grid(row=0, column=0, padx=5)

        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.grid(row=0, column=1, padx=5)

        # Dashboard overview frame
        dashboard_frame = ttk.Labelframe(main_frame, text="Dashboard Overview", padding=(10, 10), bootstyle="info")
        dashboard_frame.grid(row=1, column=0, sticky="ew", pady=10)
        dashboard_frame.grid_columnconfigure(0, weight=1)

        self.total_events_label = ttk.Label(dashboard_frame, text="Total Events: N/A", anchor="center")
        self.total_events_label.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.unique_ips_label = ttk.Label(dashboard_frame, text="Unique IP Addresses: N/A", anchor="center")
        self.unique_ips_label.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.most_frequent_ops_label = ttk.Label(dashboard_frame, text="Most Frequent Operations: N/A", anchor="center")
        self.most_frequent_ops_label.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        # Search and filter frame
        search_frame = ttk.Labelframe(main_frame, text="Search and Filter", padding=(10, 10), bootstyle="info")
        search_frame.grid(row=2, column=0, sticky="ew", pady=10)

        self.filter_op_label = ttk.Label(search_frame, text="Filter by Operation:")
        self.filter_op_label.grid(row=0, column=0, padx=5, sticky="w")

        self.filter_op_combobox = ttk.Combobox(search_frame, state="readonly")
        self.filter_op_combobox.grid(row=0, column=1, padx=5, sticky="ew")
        self.filter_op_combobox.bind("<<ComboboxSelected>>", self.filter_by_operation)

        self.suspicious_op_btn = ttk.Button(search_frame, text="Suspicious Operations", command=self.filter_suspicious_operations, bootstyle="warning")
        self.suspicious_op_btn.grid(row=0, column=2, padx=5, sticky="w")

        self.search_label = ttk.Label(search_frame, text="Search:")
        self.search_label.grid(row=1, column=0, padx=5, pady=(10, 0), sticky="w")

        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.grid(row=1, column=1, padx=5, pady=(10, 0), sticky="w")

        self.search_btn = ttk.Button(search_frame, text="Search", command=self.search_data, bootstyle="primary")
        self.search_btn.grid(row=1, column=2, padx=5, pady=(10, 0), sticky="w")

        # IP address filter frame
        filter_frame = ttk.Labelframe(main_frame, text="IP Address Filter", padding=(10, 10), bootstyle="info")
        filter_frame.grid(row=3, column=0, sticky="ew", pady=10)

        self.ip_label = ttk.Label(filter_frame, text="Add IP Address to Filter List:")
        self.ip_label.grid(row=0, column=0, padx=5, sticky="w")

        self.ip_entry = ttk.Entry(filter_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, sticky="ew")

        self.add_ip_btn = ttk.Button(filter_frame, text="Add IP", command=self.add_ip, bootstyle="success")
        self.add_ip_btn.grid(row=0, column=2, padx=5)

        self.remove_ip_btn = ttk.Button(filter_frame, text="Remove IP", command=self.remove_ip, bootstyle="danger")
        self.remove_ip_btn.grid(row=0, column=3, padx=5)

        self.import_ip_btn = ttk.Button(filter_frame, text="Import IPs from File", command=self.import_ips_from_file, bootstyle="primary")
        self.import_ip_btn.grid(row=0, column=4, padx=5)

        # IP list frame
        list_frame = ttk.Labelframe(main_frame, text="IP List", padding=(10, 10), bootstyle="info")
        list_frame.grid(row=4, column=0, sticky="nsew", pady=10)
        main_frame.grid_rowconfigure(4, weight=1)

        self.ip_listbox = tk.Listbox(list_frame, height=10, selectmode=tk.MULTIPLE)  # Allow multiple selections
        self.ip_listbox.grid(row=0, column=0, sticky="nsew", padx=5)
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.ip_list_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.ip_listbox.yview)
        self.ip_list_scrollbar.grid(row=0, column=1, sticky="ns")

        self.ip_listbox.config(yscrollcommand=self.ip_list_scrollbar.set)

        # Detailed event log frame
        log_frame = ttk.Labelframe(main_frame, text="Parsed Data", padding=(10, 10), bootstyle="info")
        log_frame.grid(row=5, column=0, sticky="nsew", pady=10)
        main_frame.grid_rowconfigure(5, weight=1)

        self.log_text = tk.Text(log_frame, wrap=tk.NONE, height=10)
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=5)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_scrollbar_y = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_scrollbar_y.grid(row=0, column=1, sticky="ns")

        self.log_scrollbar_x = ttk.Scrollbar(log_frame, orient=tk.HORIZONTAL, command=self.log_text.xview)
        self.log_scrollbar_x.grid(row=1, column=0, sticky="ew")

        self.log_text.config(yscrollcommand=self.log_scrollbar_y.set, xscrollcommand=self.log_scrollbar_x.set)
        self.log_text.bind("<Double-1>", self.show_event_details)  # Bind double-click to show event details

        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=6, column=0, sticky="ew", pady=10)

        self.parse_btn = ttk.Button(action_frame, text="Parse and Filter", command=self.parse_and_filter, bootstyle="primary")
        self.parse_btn.grid(row=0, column=0, padx=5)

        self.enrich_ip_btn = ttk.Button(action_frame, text="Enrich IP Information", command=self.enrich_ip_info, bootstyle="primary")
        self.enrich_ip_btn.grid(row=0, column=1, padx=5)
        self.enrich_ip_btn.config(state=tk.DISABLED)

        self.save_csv_btn = ttk.Button(action_frame, text="Save Parsed CSV", command=self.save_csv, bootstyle="primary")
        self.save_csv_btn.grid(row=0, column=2, padx=5)
        self.save_csv_btn.config(state=tk.DISABLED)

        self.visualize_btn = ttk.Button(action_frame, text="Visualize Data", command=self.visualize_data, bootstyle="primary")
        self.visualize_btn.grid(row=0, column=3, padx=5)
        self.visualize_btn.config(state=tk.DISABLED)

        # Progress bar frame
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.grid(row=7, column=0, sticky="ew", pady=10)
        self.progress_frame.grid_columnconfigure(0, weight=1)

        self.progress_label = ttk.Label(self.progress_frame, text="Enrichment in progress. Please wait...")
        self.progress_label.grid(row=0, column=0, padx=5, pady=5)

        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, mode='determinate', length=400)
        self.progress_bar.grid(row=1, column=0, padx=5, pady=5)
        self.progress_frame.grid_remove()  # Hide progress frame initially

    def select_file(self):
        self.filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if self.filepath:
            self.file_label.config(text=self.filepath)

    def add_ip(self):
        ip = self.ip_entry.get().strip()
        if ip and ip not in self.ip_list:
            self.ip_list.append(ip)
            self.ip_listbox.insert(tk.END, ip)
            self.ip_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Duplicate IP", "This IP address is already in the list.")

    def remove_ip(self):
        selected_indices = self.ip_listbox.curselection()
        if selected_indices:
            for index in selected_indices[::-1]:
                display_text = self.ip_listbox.get(index)
                ip = display_text.split(" - ")[0]  # Extract the IP address
                self.ip_list.remove(ip)
                if ip in self.enriched_ip_info:
                    del self.enriched_ip_info[ip]
                self.ip_listbox.delete(index)
        else:
            messagebox.showwarning("No Selection", "Please select an IP address to remove.")

    def import_ips_from_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as file:
                ips = file.readlines()
                for ip in ips:
                    ip = ip.strip()
                    if ip and ip not in self.ip_list:
                        self.ip_list.append(ip)
                        self.ip_listbox.insert(tk.END, ip)
            messagebox.showinfo("Success", "IP addresses imported successfully!")

    def search_data(self):
        query = self.search_entry.get().strip().lower()
        if not query:
            messagebox.showwarning("No Query", "Please enter a search query.")
            return

        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "No data available to search.")
            return

        filtered_df = self.df[self.df.apply(lambda row: row.astype(str).str.lower().str.contains(query).any(), axis=1)]
        if filtered_df.empty:
            messagebox.showinfo("No Results", "No results found for the query.")
        else:
            self.df = filtered_df
            self.update_dashboard()
            self.update_event_log()
            messagebox.showinfo("Results", "Search results filtered.")

    def filter_by_operation(self, event):
        selected_operation = self.filter_op_combobox.get()
        if not selected_operation:
            messagebox.showwarning("No Operation", "Please select an operation to filter by.")
            return

        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "No data available to filter.")
            return

        filtered_df = self.df[self.df['Operation'] == selected_operation]
        if filtered_df.empty:
            messagebox.showinfo("No Results", f"No results found for the operation: {selected_operation}.")
        else:
            self.df = filtered_df
            self.update_dashboard()
            self.update_event_log()
            messagebox.showinfo("Results", f"Filtered results for the operation: {selected_operation}.")

    def filter_suspicious_operations(self):
        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "No data available to filter.")
            return

        filtered_df = self.df[self.df['Operation'].isin(self.suspicious_operations)]
        if filtered_df.empty:
            messagebox.showinfo("No Results", "No suspicious operations found.")
        else:
            self.df = filtered_df
            self.update_dashboard()
            self.update_event_log()
            messagebox.showinfo("Results", "Suspicious operations filtered.")

    def parse_and_filter(self):
        if not self.filepath:
            messagebox.showwarning("No File", "Please select a CSV file first.")
            return

        try:
            self.df = self.data_processor.parse_and_filter(self.filepath, self.ip_list)
            self.update_dashboard()
            self.update_event_log()

            # Update the filter operation combobox
            operations = self.df['Operation'].unique().tolist()
            self.filter_op_combobox['values'] = operations

            messagebox.showinfo("Success", "File parsed and filtered successfully!")

            self.enrich_ip_btn.config(state=tk.NORMAL)
            self.save_csv_btn.config(state=tk.NORMAL)
            self.visualize_btn.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def show_event_details(self, event):
        cursor_index = self.log_text.index(tk.CURRENT)
        line_number = cursor_index.split('.')[0]
        event_index = int(line_number) - 1  # Zero-based index

        if 0 <= event_index < len(self.df):
            event_data = self.df.iloc[event_index].to_json(indent=2)
            self.display_event_details(event_data)

    def display_event_details(self, event_data):
        event_window = tk.Toplevel(self.root)
        event_window.title("Event Details")

        event_text = tk.Text(event_window, wrap=tk.WORD, height=20, width=80)
        event_text.insert(tk.END, event_data)
        event_text.config(state=tk.DISABLED)  # Make the text read-only
        event_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        event_window.grid_rowconfigure(0, weight=1)
        event_window.grid_columnconfigure(0, weight=1)
        event_text.grid(row=0, column=0, sticky="nsew")

    def enrich_ip_info(self):
        if self.df is None or self.df.empty or 'ClientIP' not in self.df.columns:
            messagebox.showwarning("No Data", "No ClientIP data available to enrich.")
            return

        unique_ips = self.df['ClientIP'].dropna().unique()
        total_ips = len(unique_ips)

        self.progress_frame.grid()  # Show progress bar
        self.progress_bar["maximum"] = total_ips
        self.progress_bar["value"] = 0

        self.root.update_idletasks()

        try:
            enriched_data = self.ip_enrichment.enrich_ip_information(unique_ips, self.enriched_ip_info, self.progress_bar, self.root)
            enriched_df = pd.DataFrame(enriched_data)
            self.df = pd.merge(self.df, enriched_df, left_on='ClientIP', right_on='IP', how='left')
            self.df.drop(columns=['IP'], inplace=True)  # Remove redundant IP column from enriched data
            self.show_enriched_options(enriched_data)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while enriching IP information: {e}")
        finally:
            self.progress_frame.grid_remove()  # Hide progress bar

    def show_enriched_options(self, enriched_data):
        options_window = tk.Toplevel(self.root)
        options_window.title("Enrichment Complete")

        label = ttk.Label(options_window, text="Enrichment complete. Choose an action:")
        label.pack(pady=10)

        save_btn = ttk.Button(options_window, text="Save to CSV", command=lambda: [self.save_enriched_data(enriched_data), options_window.destroy()], bootstyle="primary")
        save_btn.pack(side=tk.LEFT, padx=10, pady=10)

        add_btn = ttk.Button(options_window, text="Add to List", command=lambda: [self.add_enriched_ips_to_list(enriched_data), options_window.destroy()], bootstyle="success")
        add_btn.pack(side=tk.RIGHT, padx=10, pady=10)

    def save_enriched_data(self, enriched_data):
        enriched_df = pd.DataFrame(enriched_data)
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if save_path:
            try:
                enriched_df.to_csv(save_path, index=False)
                messagebox.showinfo("Success", "Enriched IP information saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while saving the file: {e}")

    def add_enriched_ips_to_list(self, enriched_data):
        for enriched_info in enriched_data:
            ip = enriched_info['IP']
            display_text = f"{ip} - {enriched_info['IPEnrichment_Country']}, {enriched_info['IPEnrichment_Org']}"
            if ip not in self.ip_list:
                self.ip_list.append(ip)
                self.ip_listbox.insert(tk.END, display_text)
        messagebox.showinfo("Success", "Enriched IPs added to the filter list.")

    def save_csv(self):
        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "No parsed data available to save.")
            return
        save_file(self.df, "Save Parsed CSV")

    def visualize_data(self):
        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "No data available to visualize.")
            return

        try:
            self.current_visualization_index = 0
            self.visualizations = self.visualization.create_visualizations(self.df)
            self.show_current_visualization()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while creating visualizations: {e}")

    def show_current_visualization(self):
        if not self.visualizations:
            return

        fig = self.visualizations[self.current_visualization_index]

        vis_window = tk.Toplevel(self.root)
        vis_window.title("Visualization")

        canvas = FigureCanvasTkAgg(fig, master=vis_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        nav_frame = ttk.Frame(vis_window)
        nav_frame.pack()

        prev_btn = ttk.Button(nav_frame, text="Previous", command=lambda: self.show_previous_visualization(vis_window), bootstyle="primary")
        prev_btn.grid(row=0, column=0, padx=5, pady=5)

        next_btn = ttk.Button(nav_frame, text="Next", command=lambda: self.show_next_visualization(vis_window), bootstyle="primary")
        next_btn.grid(row=0, column=1, padx=5, pady=5)

    def show_previous_visualization(self, vis_window):
        vis_window.destroy()
        self.current_visualization_index = (self.current_visualization_index - 1) % len(self.visualizations)
        self.show_current_visualization()

    def show_next_visualization(self, vis_window):
        vis_window.destroy()
        self.current_visualization_index = (self.current_visualization_index + 1) % len(self.visualizations)
        self.show_current_visualization()

    def update_dashboard(self):
        if self.df is not None:
            total_events = len(self.df)
            unique_ips = self.df['ClientIP'].nunique()
            most_frequent_ops = self.df['Operation'].value_counts().nlargest(5).to_dict()

            self.total_events_label.config(text=f"Total Events: {total_events}")
            self.unique_ips_label.config(text=f"Unique IP Addresses: {unique_ips}")
            self.most_frequent_ops_label.config(text=f"Most Frequent Operations: {most_frequent_ops}")

    def update_event_log(self):
        if self.df is not None:
            self.log_text.delete('1.0', tk.END)
            for index, row in self.df.iterrows():
                self.log_text.insert(tk.END, f"Event {index + 1}: {row.to_json()}\n")
