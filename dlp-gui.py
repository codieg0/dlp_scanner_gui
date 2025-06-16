import tkinter as tk
from tkinter import filedialog, messagebox, ttk, PhotoImage
import pyperclip
import json
import re
import os
import PyPDF2

# --- Load Dictionary Terms from json file ---
def load_dlp_dict(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    dlp_dict = {}
    for category, terms in data.items():
        for term in terms:
            dlp_dict[term.strip()] = category
    return dlp_dict

# --- Dictionary-based term search ---
def find_dlp_terms(text, dlp_dict, selected_terms=None):
    found = []
    for term, category in dlp_dict.items():
        if selected_terms and term not in selected_terms:
            continue
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        if pattern.search(text):
            found.append((term, category))
    return found

# --- Enhanced SSN detection ---
def find_ssn(text):
    formatted = re.findall(r'\b(?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', text)
    unformatted = re.findall(r'\b(?!666|000|9\d{2})\d{9}\b', text)
    excluded_range = set(str(i) for i in range(87654320, 87654330))
    filtered_unformatted = [ssn for ssn in unformatted if ssn not in excluded_range]
    return list(set(formatted + filtered_unformatted))

# --- Luhn Algorithm for Credit Cards ---
def luhn_check(card_number):
    digits = [int(d) for d in card_number if d.isdigit()]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0

def find_credit_cards(text):
    cc_patterns = [
        r'\b3[47]\d{13}\b',                     # Amex
        r'\b3(0[0-5]|[68]\d)\d{11}\b',          # Diners Club
        r'\b6011\d{12}\b',                      # Discover
        r'\b5[1-5]\d{14}\b',                    # MasterCard
        r'\b62\d{14}\b',                        # Union Pay
        r'\b4\d{12}(\d{3})?\b'                  # Visa
    ]
    found = set()
    for pattern in cc_patterns:
        for match in re.findall(pattern, text):
            match_str = ''.join(match) if isinstance(match, tuple) else match
            if luhn_check(match_str):
                found.add(match_str)
    return list(found)

# --- Basic US Driver License detection ---
def find_us_driver_license(text):
    patterns = [
        r'\b\d{5,13}\b',
        r'\b[A-Z]{1,2}\d{5,13}\b'
    ]
    found = set()
    for pattern in patterns:
        found.update(re.findall(pattern, text))
    return list(found)

# --- File text extraction ---
def extract_text_from_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    try:
        if ext == ".txt":
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return [("body", f.read())]
        elif ext == ".pdf":
            with open(filepath, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                return [("body", "\n".join(page.extract_text() or "" for page in reader.pages))]
        elif ext == ".docx":
            from docx import Document
            doc = Document(filepath)
            return [("body", "\n".join([para.text for para in doc.paragraphs]))]
        elif ext == ".eml":
            from email import policy
            from email.parser import BytesParser
            import tempfile
            with open(filepath, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)
            subject = msg['subject'] or ""
            body = ""
            sources = []
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype == "text/plain":
                        body += part.get_content()
                    elif part.get_filename():
                        filename = part.get_filename()
                        payload = part.get_payload(decode=True)
                        if payload:
                            ext = os.path.splitext(filename)[1].lower()
                            if ext in [".txt", ".pdf", ".docx"]:
                                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                                    tmp.write(payload)
                                    tmp_path = tmp.name
                                # Recursively extract from attachment
                                for src, txt in extract_text_from_file(tmp_path):
                                    sources.append((f"attachment: {filename}", txt))
                                os.unlink(tmp_path)
            else:
                body = msg.get_content()
            sources.insert(0, ("body", f"{subject}\n{body}"))
            return sources
        else:
            return []
    except Exception as e:
        return [("body", f"[Error reading {filepath}: {e}]")]

# --- Main scan logic with source grouping ---
def scan_files(files, scan_options, dlp_dict_path=None, dict_terms=None):
    results_by_file = {}
    dlp_dict = load_dlp_dict(dlp_dict_path) if dlp_dict_path else {}
    for f in files:
        fname = os.path.basename(f)
        matches = []
        sources = extract_text_from_file(f)
        if not sources:
            matches.append(("no_text", "  [No text extracted]", "body"))
        else:
            for source, text in sources:
                if "SSN" in scan_options:
                    for ssn in find_ssn(text):
                        matches.append(("ssn", f"• {ssn}   [SSN]", source))
                if "Credit Card" in scan_options:
                    for cc in find_credit_cards(text):
                        matches.append(("creditcard", f"• {cc}   [Credit Card]", source))
                if "US Driver License" in scan_options:
                    for lic in find_us_driver_license(text):
                        matches.append(("usdl", f"• {lic}   [US Driver License]", source))
                if "Dictionary" in scan_options and dlp_dict:
                    dict_matches = find_dlp_terms(text, dlp_dict, dict_terms if dict_terms and dict_terms != ["ALL"] else None)
                    for term, category in dict_matches:
                        matches.append(("category", f"• {term}   [{category}]", source))
        if not matches:
            matches.append(("no_match", "  [No matches found]", "body"))
        results_by_file.setdefault(fname, []).extend(matches)
    return results_by_file

# --- GUI ---
root = tk.Tk()
root.title("DLP Scanner GUI")
root.iconbitmap(os.path.join(os.path.dirname(__file__), 'icon.ico'))

# Show privacy warning popup (English & Spanish)
messagebox.showwarning(
    "Privacy Warning / Advertencia de Privacidad",
    "⚠️ This tool scans sensitive data.\nPlease keep the output private and secure.\n\n"
    "⚠️ Esta herramienta analiza datos sensibles.\nPor favor, mantenga el contenido en privado."
)

# Set default font and background color
default_font = ("Segoe UI", 12)
root.option_add("*Font", default_font)
root.configure(bg="#f4f6fb")

# Set the icon
icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')
try:
    root.iconbitmap(icon_path)
except Exception as e:
    print(f"Could not set icon: {e}")

# Store a mapping from displayed name to full path
file_display_to_path = {}
# Store the full path of the selected dictionary file (for internal use)
dict_full_path = None

def select_files():
    global file_display_to_path
    files = filedialog.askopenfilenames(title="Select files to scan")
    file_list.delete(0, tk.END)
    file_display_to_path = {}
    for f in files:
        fname = os.path.basename(f)
        file_list.insert(tk.END, fname)
        file_display_to_path[fname] = f

def select_dict_file():
    global dict_full_path
    path = filedialog.askopenfilename(title="Select dictionary JSON file", filetypes=[("JSON files", "*.json")])
    if path:
        dict_full_path = path  # Store the full path for internal use
        dict_path_var.set(os.path.basename(path))  # Show only the filename in the entry

# Add a logo/banner (optional: replace 'logo.png' with your image file)
try:
    logo_img = PhotoImage(file="logo.png")
    logo_label = tk.Label(root, image=logo_img, bg="#f4f6fb")
    logo_label.pack(pady=(10, 0))
except Exception:
    logo_label = tk.Label(root, text="DLP Scanner", font=("Segoe UI", 18, "bold"), bg="#f4f6fb", fg="#2a3b8f")
    logo_label.pack(pady=(10, 0))

container = ttk.Frame(root, style="Card.TFrame")
container.pack(expand=True, fill="both")

frame = ttk.Frame(container, padding=20, style="Card.TFrame")
frame.pack(anchor="center")

style = ttk.Style()
style.configure("Card.TFrame", background="#f4f6fb")
style.configure("TButton", padding=6)
style.configure("TCheckbutton", background="#f4f6fb")
style.configure("TLabel", background="#f4f6fb")

# Section heading
ttk.Label(frame, text="Attachments", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, columnspan=4, pady=(0, 5))

select_btn = ttk.Button(frame, text="Select Files", command=select_files)
select_btn.grid(row=1, column=0, sticky="ew", pady=(0, 8), columnspan=4)

file_list = tk.Listbox(frame, width=60, height=5, borderwidth=2, relief="groove", highlightthickness=0)
file_list.grid(row=2, column=0, columnspan=4, pady=(0, 12), sticky="ew")

# Section heading
ttk.Label(frame, text="Scan Options", font=("Segoe UI", 13, "bold")).grid(row=3, column=0, columnspan=4, pady=(0, 5))

var_ssn = tk.BooleanVar(value=False)
var_cc = tk.BooleanVar(value=False)
var_dl = tk.BooleanVar(value=False)
var_dict = tk.BooleanVar(value=False)
var_dict_specific = tk.BooleanVar(value=False)
dict_path_var = tk.StringVar(value="")

ssn_cb = ttk.Checkbutton(frame, text="SSN", variable=var_ssn)
ssn_cb.grid(row=4, column=0, sticky="ew", padx=2)
cc_cb = ttk.Checkbutton(frame, text="Credit Card", variable=var_cc)
cc_cb.grid(row=4, column=1, sticky="ew", padx=2)
dl_cb = ttk.Checkbutton(frame, text="US Driver License", variable=var_dl)
dl_cb.grid(row=4, column=2, sticky="ew", padx=2)
dict_cb = ttk.Checkbutton(frame, text="Dictionary", variable=var_dict)
dict_cb.grid(row=4, column=3, sticky="ew", padx=2)
specific_cb = ttk.Checkbutton(frame, text="Specific Dict Terms", variable=var_dict_specific)
specific_cb.grid(row=5, column=3, sticky="ew", padx=2)

select_dict_btn = ttk.Button(frame, text="Select Dictionary JSON", command=select_dict_file)
select_dict_btn.grid(row=5, column=0, sticky="ew", pady=5, columnspan=1)
dict_entry = ttk.Entry(frame, textvariable=dict_path_var, width=40)
dict_entry.grid(row=5, column=1, columnspan=2, sticky="ew", padx=2)

# Progress bar
progress = ttk.Progressbar(frame, mode="indeterminate")
progress.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(8, 0))
progress.grid_remove()

# --- Output Text Widget with Color Tags ---
output_label = ttk.Label(frame, text="Results:")
output_label.grid(row=8, column=0, columnspan=4, sticky="ew", pady=(10, 0))

output_text = tk.Text(frame, width=80, height=12, state="disabled", bg="#f8fafc", relief="flat", borderwidth=2)
output_text.grid(row=9, column=0, columnspan=4, pady=5, sticky="ew")

# Configure color tags
output_text.tag_config("filename", foreground="#2a3b8f", font=("Segoe UI", 11, "bold"))
output_text.tag_config("ssn", foreground="#e67e22")
output_text.tag_config("creditcard", foreground="#27ae60")
output_text.tag_config("usdl", foreground="#2980b9")
output_text.tag_config("category", foreground="#8e44ad")
output_text.tag_config("source", foreground="#888888", font=("Segoe UI", 10, "italic"))
output_text.tag_config("no_text", foreground="#c0392b")
output_text.tag_config("no_match", foreground="#888888")

def set_output_text(results_by_file):
    output_text.config(state="normal")
    output_text.delete(1.0, tk.END)
    for fname, matches in results_by_file.items():
        output_text.insert(tk.END, f"{fname}\n", "filename")
        # Organize matches by source
        body_matches = []
        attachments = {}
        for tag, m, source in matches:
            if source == "body":
                body_matches.append((tag, m))
            elif source.startswith("attachment: "):
                att_name = source.replace("attachment: ", "")
                attachments.setdefault(att_name, []).append((tag, m))
        # Body/subject
        if body_matches:
            output_text.insert(tk.END, "\tBody/subject\n", "source")
            for tag, m in body_matches:
                output_text.insert(tk.END, f"\t\t{m}\n", tag)
        # Attachments
        for att_name, att_matches in attachments.items():
            output_text.insert(tk.END, f"\tAttachment - {att_name}\n", "source")
            for tag, m in att_matches:
                output_text.insert(tk.END, f"\t\t{m}\n", tag)
        output_text.insert(tk.END, "\n")
    output_text.config(state="disabled")

def run_scan():
    selected_names = file_list.get(0, tk.END)
    files = [file_display_to_path[name] for name in selected_names]
    if not files:
        messagebox.showwarning("No files", "Please select files to scan.")
        return
    scan_options = []
    if var_ssn.get(): scan_options.append("SSN")
    if var_cc.get(): scan_options.append("Credit Card")
    if var_dl.get(): scan_options.append("US Driver License")
    dict_terms = None
    # Use the full path for scanning
    dlp_dict_path = dict_full_path if var_dict.get() else None
    if var_dict.get():
        scan_options.append("Dictionary")
        if not dlp_dict_path:
            messagebox.showwarning("No dictionary", "Please select a dictionary JSON file.")
            return
        if var_dict_specific.get():
            dlp_dict = load_dlp_dict(dlp_dict_path)
            with open(dlp_dict_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            all_categories = sorted(data.keys())
            cat_win = tk.Toplevel(root)
            cat_win.title("Select Dictionary Categories")
            cat_win.geometry("400x400")
            lb_frame = ttk.Frame(cat_win)
            lb_frame.pack(fill="both", expand=True, pady=10)
            lb = tk.Listbox(lb_frame, selectmode=tk.MULTIPLE, width=50, height=8)
            lb.pack(side="left", fill="both", expand=True)
            scrollbar = ttk.Scrollbar(lb_frame, orient="vertical", command=lb.yview)
            scrollbar.pack(side="right", fill="y")
            lb.config(yscrollcommand=scrollbar.set)
            for c in all_categories:
                lb.insert(tk.END, c)
            selected_categories = []
            def set_categories():
                selected = [all_categories[i] for i in lb.curselection()]
                nonlocal dict_terms
                dict_terms = []
                for cat in selected:
                    dict_terms.extend(data[cat])
                cat_win.destroy()
            ttk.Button(cat_win, text="OK", command=set_categories).pack(pady=8)
            root.wait_window(cat_win)
            if not dict_terms:
                messagebox.showwarning("No categories", "No dictionary categories selected.")
                return
    # Show progress bar
    progress.grid()
    progress.start()
    root.update_idletasks()
    results_by_file = scan_files(files, scan_options, dlp_dict_path, dict_terms)
    progress.stop()
    progress.grid_remove()
    set_output_text(results_by_file)
    # Copy plain text to clipboard (without color)
    plain_lines = []
    for fname, matches in results_by_file.items():
        plain_lines.append(fname)
        # Organize matches by source for clipboard as well
        body_matches = []
        attachments = {}
        for tag, m, source in matches:
            if source == "body":
                body_matches.append(m)
            elif source.startswith("attachment: "):
                att_name = source.replace("attachment: ", "")
                attachments.setdefault(att_name, []).append(m)
        if body_matches:
            plain_lines.append("\tBody/subject")
            for m in body_matches:
                plain_lines.append(f"\t\t{m}")
        for att_name, att_matches in attachments.items():
            plain_lines.append(f"\tAttachment - {att_name}")
            for m in att_matches:
                plain_lines.append(f"\t\t{m}")
        plain_lines.append("")
    pyperclip.copy("\n".join(plain_lines).strip())
    messagebox.showinfo("Copied", "Results copied to clipboard.")

run_btn = ttk.Button(frame, text="Run Scan", command=run_scan)
run_btn.grid(row=7, column=0, columnspan=4, pady=12, sticky="ew")

# Make columns expand equally for centering
for i in range(4):
    frame.grid_columnconfigure(i, weight=1)

root.mainloop()