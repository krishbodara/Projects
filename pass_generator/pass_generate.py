import string
import random
import tkinter as tk
from tkinter import messagebox, scrolledtext

def generate_random_passwords(character_pool, length, num_passwords):
    passwords = set()  # Use a set to avoid duplicates
    while len(passwords) < num_passwords:
        password = ''.join(random.choice(character_pool) for _ in range(length))
        passwords.add(password)
    return list(passwords)

def generate_all_passwords(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special_chars=True):
    # Create a pool of characters based on user preferences
    character_pool = ''
    
    if use_uppercase:
        character_pool += string.ascii_uppercase
    if use_lowercase:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    if use_special_chars:
        character_pool += string.punctuation

    # Ensure the character pool is not empty
    if not character_pool:
        raise ValueError("At least one character type must be selected.")

    return character_pool

def save_passwords_to_file(passwords, filename='passwords.txt'):
    with open(filename, 'w', encoding='utf-8') as file:
        for password in passwords:
            file.write(password + '\n')

def generate_passwords():
    try:
        length = int(length_entry.get())
        num_passwords = int(num_passwords_entry.get())  # Get the number of passwords to generate
        use_uppercase = uppercase_var.get()
        use_lowercase = lowercase_var.get()
        use_digits = digits_var.get()
        use_special_chars = special_chars_var.get()

        # Generate character pool
        character_pool = generate_all_passwords(length, use_uppercase, use_lowercase, use_digits, use_special_chars)

        # Generate random passwords
        passwords = generate_random_passwords(character_pool, length, num_passwords)

        # Save passwords to a file
        save_passwords_to_file(passwords)
        output_text.delete(1.0, tk.END)  # Clear previous output
        output_text.insert(tk.END, f"{len(passwords)} random passwords of length {length} have been saved to 'passwords.txt'.\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("800x600")  # Set initial size
root.configure(bg="#f0f0f0")  

# Create input fields
tk.Label(root, text="Password Length:", bg="#f0f0f0", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10, sticky='w')
length_entry = tk.Entry(root, width=10, font=("Arial", 12))
length_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')

tk.Label(root, text="Number of Passwords:", bg="#f0f0f0", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10, sticky='w')
num_passwords_entry = tk.Entry(root, width=10, font=("Arial", 12))
num_passwords_entry.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

uppercase_var = tk.BooleanVar(value=True)
tk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var, bg="#f0f0f0", font=("Arial", 12)).grid(row=2, columnspan=2, padx=10, pady=5, sticky='w')

lowercase_var = tk.BooleanVar(value=True)
tk.Checkbutton(root, text="Include Lowercase Letters", variable=lowercase_var, bg="#f0f0f0", font=("Arial", 12)).grid(row=3, columnspan=2, padx=10, pady=5, sticky='w')

digits_var = tk.BooleanVar(value=True)
tk.Checkbutton(root, text="Include Digits", variable=digits_var, bg="#f0f0f0", font=("Arial", 12)).grid(row=4, columnspan=2, padx=10, pady=5, sticky='w')

special_chars_var = tk.BooleanVar(value=True)
tk.Checkbutton(root, text="Include Special Characters", variable=special_chars_var, bg="#f0f0f0", font=("Arial", 12)).grid(row=5, columnspan=2, padx=10, pady=5, sticky='w')

# Create buttons frame
button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.grid(row=6, columnspan=2, pady=20)

# Generate button
generate_button = tk.Button(button_frame, text="Generate Passwords", command=generate_passwords, bg="#4CAF50", fg="white", font=("Arial", 12), width=20)
generate_button.grid(row=0, column=0, padx=10)

# Output text area
output_text = scrolledtext.ScrolledText(root, width=80, height=15, bg="#ffffff", fg="#000000", font=("Arial", 12))
output_text.grid(row=7, columnspan=2, padx=10, pady=10)

for i in range(2):
    root.grid_columnconfigure(i, weight=1)

# Start the GUI event loop
root.mainloop()
