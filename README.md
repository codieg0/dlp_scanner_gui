# DLP Scanner GUI - Quick Start Guide

This tool scans emails and attachments for sensitive information (SSN, credit card, US driver license, and custom dictionary terms) using a simple graphical interface.

---

## How to Use (Executable Version)

1. Download and unzip the folder containing:
    - `dlp-gui.exe`
    - `icon.ico`
    - The dictionary JSON
2. Use the GUI to select files, scan options, and dictionary.
<!-- 4. Open Powershell as administrator and run this to create a shortcut for the executable in your Desktop.
```powershell
$ShortcutPath = "$env:PUBLIC\Desktop\\DLP-Scanner.lnk"; $TargetPath = "C:\Users\$env:USERNAME\Desktop\DLP\dist\dlp-gui.exe"; $WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut($ShortcutPath); $Shortcut.TargetPath = $TargetPath; $Shortcut.Save()
``` -->
<!-- ## How to Use (Python Version)

1. Download and unzip the folder containing:
    - `dlp-gui.py`
    - `icon.ico`
    - `requirements.txt`
2. Install Python 3 if not already installed: [python.org/downloads](https://www.python.org/downloads/)
3. Open Powershell in the folder and run:
    ```powershell
    py.exe -m pip install -r requirements.txt
    ```
 -->
## Dictionary File

- You can select all or specific categories in the GUI.

## Troubleshooting

- If the icon or logo does not appear, make sure the files are in the same folder as the `.exe` or `.py` file.
- If you see an error about missing modules, run: `pip install -r requirements.txt`
- For best results, use `.ico` for the icon.

## Contact

For questions or issues, contact me and share screenshots and all the information you can.