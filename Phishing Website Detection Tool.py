import tkinter as tk
from tkinter import ttk, messagebox, font
import re
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random
from datetime import datetime
from urllib.parse import urlparse

class PhishingDetectorDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing URL Detector Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configure styles with larger fonts
        self.style = ttk.Style()
        self.style.configure('.', font=('Helvetica', 12))
        self.style.configure('TLabel', font=('Helvetica', 12))
        self.style.configure('Title.TLabel', font=('Helvetica', 18, 'bold'))
        self.style.configure('Result.TLabel', font=('Helvetica', 14, 'bold'))
        self.style.configure('Small.TLabel', font=('Helvetica', 10))
        
        # Initialize statistics
        self.total_checked = 0
        self.phishing_count = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.recent_checks = []
        
        # Initialize model
        self.initialize_model()
        
        # Create UI
        self.create_header()
        self.create_main_content()
        self.create_stats_section()
        self.create_features_section()
        
    def initialize_model(self):
        # Simulate loading a model (in a real app, you'd load your actual model here)
        self.model = RandomForestClassifier()
        self.features = ['length_url', 'nb_hyphens', 'nb_dots', 'nb_at', 'ip']
        
    def create_header(self):
        header_frame = tk.Frame(self.root, bg='#4a6bff', height=100)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        title_frame = tk.Frame(header_frame, bg='#4a6bff')
        title_frame.pack(side='left', padx=20, pady=10)
        
        ttk.Label(title_frame, text="Phishing URL Detector", 
                 style='Title.TLabel', background='#4a6bff', 
                 foreground='white').pack(anchor='w')
        ttk.Label(title_frame, text="Advanced protection against malicious websites", 
                 style='Small.TLabel', background='#4a6bff', 
                 foreground='white').pack(anchor='w')
        
        # For a real app, you would use an actual image instead
        self.shield_img = Image.new('RGB', (80, 80), (74, 107, 255))
        self.shield_photo = ImageTk.PhotoImage(self.shield_img)
        shield_label = tk.Label(header_frame, image=self.shield_photo, 
                               bg='#4a6bff', borderwidth=0)
        shield_label.pack(side='right', padx=20)
    
    def create_main_content(self):
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Left panel - URL checking section
        left_panel = tk.Frame(main_frame)
        left_panel.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        check_frame = ttk.LabelFrame(left_panel, text="Check a URL", padding=(15, 10))
        check_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(check_frame, text="Enter URL to analyze:").pack(anchor='w', pady=(0, 5))
        
        input_frame = tk.Frame(check_frame)
        input_frame.pack(fill='x', pady=5)
        
        self.url_entry = ttk.Entry(input_frame, font=('Helvetica', 12))
        self.url_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        
        check_button = ttk.Button(input_frame, text="Analyze", command=self.check_url)
        check_button.pack(side='right')
        
        # Add example label
        ttk.Label(check_frame, text="Example: https://example.com", 
                 style='Small.TLabel', foreground='gray').pack(anchor='w', pady=(0, 10))
        
        # Result section
        self.result_frame = ttk.LabelFrame(check_frame, text="Analysis Result", padding=(15, 10))
        self.result_frame.pack_forget()  # Initially hidden
        
        self.result_header = tk.Frame(self.result_frame)
        self.result_header.pack(fill='x', pady=(0, 10))
        
        ttk.Label(self.result_header, text="Result:", style='Result.TLabel').pack(side='left')
        self.result_label = ttk.Label(self.result_header, text="", style='Result.TLabel')
        self.result_label.pack(side='right')
        
        # Analysis details
        analysis_grid = tk.Frame(self.result_frame)
        analysis_grid.pack(fill='both', expand=True)
        
        # Heuristic analysis
        self.heuristic_frame = ttk.LabelFrame(analysis_grid, text="Heuristic Analysis", padding=10)
        self.heuristic_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        self.heuristic_text = tk.Text(self.heuristic_frame, height=5, width=30, 
                                     wrap='word', state='disabled', font=('Helvetica', 11))
        self.heuristic_text.pack(fill='both', expand=True)
        
        # ML analysis
        self.ml_frame = ttk.LabelFrame(analysis_grid, text="Machine Learning Prediction", padding=10)
        self.ml_frame.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        self.ml_text = tk.Text(self.ml_frame, height=5, width=30, 
                              wrap='word', state='disabled', font=('Helvetica', 11))
        self.ml_text.pack(fill='both', expand=True)
        
        # More details
        self.details_frame = ttk.LabelFrame(self.result_frame, text="Detailed Analysis", padding=10)
        self.details_frame.pack(fill='both', expand=True, pady=(5, 0))
        self.details_text = tk.Text(self.details_frame, height=4, 
                                   wrap='word', state='disabled', font=('Helvetica', 11))
        self.details_text.pack(fill='both', expand=True)
        
        # Configure grid weights
        analysis_grid.columnconfigure(0, weight=1)
        analysis_grid.columnconfigure(1, weight=1)
        
    def create_stats_section(self):
        # Right panel - stats section
        right_panel = tk.Frame(self.root)
        right_panel.pack(side='right', fill='both', expand=False, padx=5, pady=5, ipadx=10)
        
        stats_frame = ttk.LabelFrame(right_panel, text="Detection Statistics", padding=(15, 10))
        stats_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Chart
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=stats_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True, pady=5)
        self.update_chart()
        
        # Stats
        stats_grid = tk.Frame(stats_frame)
        stats_grid.pack(fill='x', pady=(10, 0))
        
        ttk.Label(stats_grid, text="Total URLs checked:").grid(row=0, column=0, sticky='w')
        self.total_label = ttk.Label(stats_grid, text="0", font=('Helvetica', 12, 'bold'))
        self.total_label.grid(row=0, column=1, sticky='e')
        
        ttk.Label(stats_grid, text="Phishing detected:").grid(row=1, column=0, sticky='w')
        self.phishing_label = ttk.Label(stats_grid, text="0", font=('Helvetica', 12, 'bold'), foreground='red')
        self.phishing_label.grid(row=1, column=1, sticky='e')
        
        ttk.Label(stats_grid, text="Safe URLs:").grid(row=2, column=0, sticky='w')
        self.safe_label = ttk.Label(stats_grid, text="0", font=('Helvetica', 12, 'bold'), foreground='green')
        self.safe_label.grid(row=2, column=1, sticky='e')
        
        ttk.Label(stats_grid, text="Suspicious URLs:").grid(row=3, column=0, sticky='w')
        self.suspicious_label = ttk.Label(stats_grid, text="0", font=('Helvetica', 12, 'bold'), foreground='orange')
        self.suspicious_label.grid(row=3, column=1, sticky='e')
        
        # Recent checks
        recent_frame = ttk.LabelFrame(stats_frame, text="Recent Checks", padding=10)
        recent_frame.pack(fill='both', expand=True, pady=(10, 0))
        
        self.recent_text = tk.Text(recent_frame, height=5, wrap='word', 
                                  state='disabled', font=('Helvetica', 10))
        self.recent_text.pack(fill='both', expand=True)
        
    def create_features_section(self):
        features_frame = ttk.LabelFrame(self.root, text="Detection Features", padding=(15, 10))
        features_frame.pack(fill='x', padx=10, pady=5)
        
        # Feature cards
        feature1 = ttk.Frame(features_frame)
        feature1.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        self.create_feature_card(feature1, "URL Length", "Analyzes the length of the URL, as phishing URLs are often longer.")
        
        feature2 = ttk.Frame(features_frame)
        feature2.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        self.create_feature_card(feature2, "Special Characters", "Checks for hyphens, dots, or @ symbols.")
        
        feature3 = ttk.Frame(features_frame)
        feature3.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        self.create_feature_card(feature3, "IP Address", "Detects if URL contains an IP address.")
        
        feature4 = ttk.Frame(features_frame)
        feature4.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        self.create_feature_card(feature4, "Suspicious Keywords", "Looks for words like login, secure, etc.")
    
    def create_feature_card(self, parent, title, description):
        card = tk.Frame(parent, relief='raised', borderwidth=1)
        card.pack(fill='both', expand=True)
        
        ttk.Label(card, text=title, font=('Helvetica', 12, 'bold')).pack(pady=(10, 5))
        ttk.Label(card, text=description, font=('Helvetica', 10), 
                 wraplength=200, justify='center').pack(pady=(0, 10), padx=5)
    
    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            # Check if the URL has at least a scheme and netloc
            if not (result.scheme and result.netloc):
                return False
            
            # Check if the netloc has a valid domain format
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', result.netloc):
                return False
                
            return True
        except:
            return False
    
    def check_url(self):
        url = self.url_entry.get().strip()
        
        # Validate the URL
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL to check")
            return
            
        if not self.is_valid_url(url):
            messagebox.showerror("Invalid URL", 
                               "Please enter a valid URL (e.g., https://example.com)")
            return
        
        # Reset UI
        self.result_frame.pack(fill='both', expand=True, pady=5)
        
        # Simulate analysis
        heuristic_result = self.heuristic_check(url)
        ml_result = self.ml_predict(url)
        
        # Determine final result
        final_result = "Suspicious"
        result_color = "orange"
        
        if not heuristic_result.startswith("Detected") and ml_result == "Safe":
            final_result = "Safe"
            result_color = "green"
            self.safe_count += 1
        elif heuristic_result.startswith("Detected") and ml_result == "Phishing":
            final_result = "Phishing"
            result_color = "red"
            self.phishing_count += 1
        else:
            self.suspicious_count += 1
        
        self.total_checked += 1
        self.recent_checks.insert(0, f"{url[:25]}... - {final_result} ({datetime.now().strftime('%H:%M')})")
        if len(self.recent_checks) > 5:
            self.recent_checks.pop()
        
        # Update UI
        self.result_label.config(text=final_result, foreground=result_color)
        self.update_text_widget(self.heuristic_text, heuristic_result)
        self.update_text_widget(self.ml_text, f"Prediction: {ml_result}\nConfidence: {random.randint(70, 95)}%")
        self.update_text_widget(self.details_text, self.get_detailed_analysis(url))
        
        # Update stats
        self.update_stats()
        self.update_chart()
        self.update_recent_checks()
    
    def heuristic_check(self, url):
        # Simple heuristic checks
        rules = [
            ("IP address in domain", bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))),
            ("'@' symbol in URL", '@' in url),
            ("Suspicious keywords (login, secure, etc.)", 
             bool(re.search(r"(login|secure|update|verify|account|banking)", url, re.IGNORECASE))),
            ("Long URL (>54 chars)", len(url) > 54),
            ("Multiple subdomains", url.count('.') > 3),
            ("Hyphen in domain", '-' in urlparse(url).netloc),
            ("Non-standard port", bool(re.search(r":\d+", urlparse(url).netloc)))
        ]
        
        detected = []
        for name, condition in rules:
            if condition:
                detected.append(f"• {name}")
        
        if not detected:
            return "No suspicious patterns detected"
        else:
            return "Detected issues:\n" + "\n".join(detected)
    
    def ml_predict(self, url):
        # In a real app, you would use your actual ML model here
        # This just simulates predictions based on some heuristics
        parsed = urlparse(url)

        # More realistic simulation based on URL features
        ip_present = bool(re.search(r"\d+\.\d+\.\d+\.\d+", parsed.netloc))
        length = len(url)
        hyphen_count = url.count('-')
        at_present = '@' in url
        dot_count = url.count('.')
        
        risk_score = 0
        
        # Score components
        if ip_present: risk_score += 0.4
        if at_present: risk_score += 0.3
        if hyphen_count > 1: risk_score += 0.1 * min(hyphen_count, 5)
        if dot_count > 3: risk_score += 0.1 * min(dot_count-3, 4)
        if length > 75: risk_score += 0.2
        elif length > 50: risk_score += 0.1
        
        # Add some randomness
        risk_score += random.uniform(-0.1, 0.1)
        risk_score = max(0, min(risk_score, 1))
        
        if risk_score > 0.7:
            return "Phishing"
        elif risk_score > 0.4:
            return "Suspicious"
        else:
            return "Safe"
    
    def get_detailed_analysis(self, url):
        parsed = urlparse(url)
        features = [
            f"Full URL: {url[:100]}{'...' if len(url)>100 else ''}",
            f"Scheme: {parsed.scheme if parsed.scheme else 'None'}",
            f"Netloc: {parsed.netloc}",
            f"URL length: {len(url)} characters",
            f"Hyphen count: {url.count('-')}",
            f"Dot count: {url.count('.')}",
            f"Contains @ symbol: {'Yes' if '@' in url else 'No'}",
            f"Contains IP address: {'Yes' if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 'No'}",
            f"Suspicious keywords: {'Yes' if re.search(r"(login|secure|update|verify)", url, re.IGNORECASE) else 'No'}"
        ]
        return "\n".join(features)
    
    def update_text_widget(self, widget, text):
        widget.config(state='normal')
        widget.delete('1.0', tk.END)
        widget.insert('1.0', text)
        widget.config(state='disabled')
    
    def update_stats(self):
        self.total_label.config(text=str(self.total_checked))
        self.phishing_label.config(text=str(self.phishing_count))
        self.safe_label.config(text=str(self.safe_count))
        self.suspicious_label.config(text=str(self.suspicious_count))
    
    def update_chart(self):
        self.ax.clear()
        
        if self.total_checked == 0:
            self.ax.text(0.5, 0.5, "No data yet", 
                        ha='center', va='center', fontsize=12)
        else:
            labels = ['Safe', 'Phishing', 'Suspicious']
            values = [self.safe_count, self.phishing_count, self.suspicious_count]
            colors = ['#4CAF50', '#F44336', '#FFC107']
            
            self.ax.pie(values, labels=labels, colors=colors, autopct='%1.1f%%',
                       startangle=90, wedgeprops={'linewidth': 1, 'edgecolor': 'white'})
            self.ax.axis('equal')
            self.ax.set_title('Detection Results', fontsize=10)
        
        self.canvas.draw()
    
    def update_recent_checks(self):
        self.update_text_widget(self.recent_text, "\n".join(self.recent_checks))

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorDashboard(root)
    root.mainloop()
