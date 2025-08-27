import requests
from bs4 import BeautifulSoup
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import ttk  # Import ttk for Progressbar
import time  # Import time for sleep functionality

class WebScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Web Scraper")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f0f0f0")

        # Title Label
        self.title_label = tk.Label(root, text="Web Scraper", bg="#f0f0f0", font=("Arial", 24, "bold"))
        self.title_label.pack(pady=10)

        # Frame for input and buttons
        self.input_frame = tk.Frame(root, bg="#f0f0f0")
        self.input_frame.pack(pady=20)

        self.url_label = tk.Label(self.input_frame, text="Enter URL:", bg="#f0f0f0", font=("Arial", 12))
        self.url_label.pack(side=tk.LEFT, padx=5)

        self.url_entry = tk.Entry(self.input_frame, width=50, font=("Arial", 12))
        self.url_entry.pack(side=tk.LEFT, padx=5)

        self.delay_label = tk.Label(self.input_frame, text="Delay (seconds):", bg="#f0f0f0", font=("Arial", 12))
        self.delay_label.pack(side=tk.LEFT, padx=5)

        self.delay_entry = tk.Entry(self.input_frame, width=5, font=("Arial", 12))
        self.delay_entry.pack(side=tk.LEFT, padx=5)
        self.delay_entry.insert(0, "1")  # Default delay of 1 second

        self.scrape_button = tk.Button(self.input_frame, text="Scrape Data", command=self.start_scraping, bg="#4CAF50", fg="white", font=("Arial", 12))
        self.scrape_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(self.input_frame, text="Save Results", command=self.save_results, state=tk.DISABLED, bg="#2196F3", fg="white", font=("Arial", 12))
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Progress Bar
        self.progress = ttk.Progressbar(root, orient="horizontal", length=800, mode="determinate")
        self.progress.pack(pady=20)

        # Frame for output
        self.output_frame = tk.Frame(root, bg="#f0f0f0")
        self.output_frame.pack(pady=10)

        # Links Output
        self.links_label = tk.Label(self.output_frame, text="Found Links:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        self.links_label.grid(row=0, column=0, padx=10, sticky='w')
        self.links_area = scrolledtext.ScrolledText(self.output_frame, width=50, height=15, font=("Arial", 12), bg="#ffffff", wrap=tk.WORD)
        self.links_area.grid(row=1, column=0, padx=10, pady=5)

        # Images Output
        self.images_label = tk.Label(self.output_frame, text="Found Images:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        self.images_label.grid(row=0, column=1, padx=10, sticky='w')
        self.images_area = scrolledtext.ScrolledText(self.output_frame, width=50, height=15, font=("Arial", 12), bg="#ffffff", wrap=tk.WORD)
        self.images_area.grid(row=1, column=1, padx=10, pady=5)

        # Headings Output
        self.headings_label = tk.Label(self.output_frame, text="Found Headings:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        self.headings_label.grid(row=2, column=0, padx=10, sticky='w')
        self.headings_area = scrolledtext.ScrolledText(self.output_frame, width=50, height=15, font=("Arial", 12), bg="#ffffff", wrap=tk.WORD)
        self.headings_area.grid(row=3, column=0, padx=10, pady=5)

        # Meta Tags Output
        self.meta_tags_label = tk.Label(self.output_frame, text="Found Meta Tags:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        self.meta_tags_label.grid(row=2, column=1, padx=10, sticky='w')
        self.meta_tags_area = scrolledtext.ScrolledText(self.output_frame, width=50, height=15, font=("Arial", 12), bg="#ffffff", wrap=tk.WORD)
        self.meta_tags_area.grid(row=3, column=1, padx=10, pady=5)

        self.links = []  # Store scraped links
        self.images = []  # Store scraped images
        self.headings = []  # Store scraped headings
        self.meta_tags = []  # Store scraped meta tags

    def start_scraping(self):
        url = self.url_entry.get()
        if url:
            self.clear_output()  # Clear previous results
            threading.Thread(target=self.scrape_data, args=(url,)).start()
        else:
            messagebox.showwarning("Input Error", "Please enter a valid URL.")

    def clear_output(self):
        self.links.clear()
        self.images.clear()
        self.headings.clear()
        self.meta_tags.clear()
        self.links_area.delete(1.0, tk.END)
        self.images_area.delete(1.0, tk.END)
        self.headings_area.delete(1.0, tk.END)
        self.meta_tags_area.delete(1.0, tk.END)
        self.progress['value'] = 0  # Reset progress bar

    def scrape_data(self, url):
        delay = float(self.delay_entry.get())  # Get the delay from the input field
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an error for bad responses
            soup = BeautifulSoup(response.text, 'html.parser')

            total_items = len(soup.find_all('a', href=True)) + len(soup.find_all('img', src=True)) + \
                          sum(len(soup.find_all(f'h{i}')) for i in range(1, 7)) + \
                          len(soup.find_all('meta'))

            current_item = 0

            # Scrape links
            for link in soup.find_all('a', href=True):
                self.links.append(link['href'])
                current_item += 1
                self.update_progress(current_item, total_items)
                time.sleep(delay)  # Rate limiting

            # Scrape images
            for img in soup.find_all('img', src=True):
                self.images.append(img['src'])
                current_item += 1
                self.update_progress(current_item, total_items)
                time.sleep(delay)  # Rate limiting

            # Scrape headings
            for i in range(1, 7):  # h1 to h6
                for heading in soup.find_all(f'h{i}'):
                    self.headings.append(heading.get_text(strip=True))
                    current_item += 1
                    self.update_progress(current_item, total_items)
                    time.sleep(delay)  # Rate limiting

            # Scrape meta tags
            for meta in soup.find_all('meta'):
                if 'name' in meta.attrs:
                    self.meta_tags.append(f"{meta['name']}: {meta.get('content', '')}")
                    current_item += 1
                    self.update_progress(current_item, total_items)
                    time.sleep(delay)  # Rate limiting

            self.display_results()
            self.save_button.config(state=tk.NORMAL)  # Enable save button
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def update_progress(self, current, total):
        """Update the progress bar based on the current and total items."""
        progress_percentage = (current / total) * 100
        self.progress['value'] = progress_percentage
        self.root.update_idletasks()  # Update the GUI

    def display_results(self):
        # Display links with numbering
        if self.links:
            for i, link in enumerate(self.links, start=1):
                self.links_area.insert(tk.END, f"{i}. {link}\n")
        else:
            self.links_area.insert(tk.END, "No links found.")

        # Display images with numbering
        if self.images:
            for i, img in enumerate(self.images, start=1):
                self.images_area.insert(tk.END, f"{i}. {img}\n")
        else:
            self.images_area.insert(tk.END, "No images found.")

        # Display headings with numbering
        if self.headings:
            for i, heading in enumerate(self.headings, start=1):
                self.headings_area.insert(tk.END, f"{i}. {heading}\n")
        else:
            self.headings_area.insert(tk.END, "No headings found.")

        # Display meta tags with numbering
        if self.meta_tags:
            for i, meta in enumerate(self.meta_tags, start=1):
                self.meta_tags_area.insert(tk.END, f"{i}. {meta}\n")
        else:
            self.meta_tags_area.insert(tk.END, "No meta tags found.")

    def save_results(self):
        file_type = [('Text files', '*.txt'), ('CSV files', '*.csv')]
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=file_type)
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as file:
                    file.write("Found Links:\n")
                    for i, link in enumerate(self.links, start=1):
                        file.write(f"{i}. {link}\n")
                    
                    file.write("\nFound Images:\n")
                    for i, img in enumerate(self.images, start=1):
                        file.write(f"{i}. {img}\n")
                    
                    file.write("\nFound Headings:\n")
                    for i, heading in enumerate(self.headings, start=1):
                        file.write(f"{i}. {heading}\n")
                    
                    file.write("\nFound Meta Tags:\n")
                    for i, meta in enumerate(self.meta_tags, start=1):
                        file.write(f"{i}. {meta}\n")
                
                messagebox.showinfo("Success", "Results saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while saving: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebScraperApp(root)
    root.mainloop()
