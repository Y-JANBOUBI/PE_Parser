
# 🛠️ PE-PARSER – Portable Executable Analyzer 
>
<img width="1195" height="495" alt="image" src="https://github.com/user-attachments/assets/2570dd96-6a7c-44aa-ae3a-fa5a4b144b87" />


<div align="center">

**Developed by Y. Janboubi** • Version `1.0`  
[![Platform](https://img.shields.io/badge/Platform-Windows_10_%7C_11-blue?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Architecture](https://img.shields.io/badge/Architecture-x64-brightgreen?logo=amd&logoColor=white)](https://en.wikipedia.org/wiki/X86-64)
[![Latest Release](https://img.shields.io/github/v/release/yourusername/PE-Parser?label=Latest%20Release&color=blue)](https://github.com/yourusername/PE-Parser/releases/latest)

</div>

## 📌 Overview
A **fast, educational, and full-featured** Portable Executable (PE) parser for Windows `.exe`, `.dll`, and `.sys` files. Perfect for reverse engineers, malware analysts, security researchers, students, and anyone who wants to deeply understand the PE format.

## 📋 Features

- **Multi-Format Support**: Analyze EXE, DLL, and SYS files
- **Comprehensive Header Parsing**: Extract DOS, NT, and Optional Header information
- **Import/Export Analysis**: Detailed listing of imported and exported functions
- **Section Analysis**: Examine code, data, relocation, and resource sections
- **Security Features**: Calculate MD5 and SHA-256 hashes for file verification
- **Architecture Detection**: Identify x86/x64 binaries
- **Verbose Mode**: Detailed output for in-depth analysis

---

## 🧪 Example Output

### **PE Info Section**

```
[+] FILE type: PE File (Valid DOS & NT Header)
[+] Reading FILE [KernelBase.dll] of Size: 4133496
[+] MD5: 2BC21FF5257...
[+] SHA-256: C7A7123A06...
```

### **Optional Header Section**

```
[+] Image Base: 0x00000001ED5B2000
[+] Entry Point: 0x000001ED2B8BF410
[+] File Checksum: 0x03F15A4U
[+] Number of DataDirectory entries: 16
```

### **Import Summary**

```
[+] Library: ntdll.dll (Functions: 737)
    [2]  CsrAllocateCaptureBuffer
    [3]  CsrAllocateMessagePointer
    [4]  CsrCaptureMessageBuffer
    ...
```
---

## 📥 Installation

### Download Latest Release (Recommended)

Go to [Releases](https://github.com/Y-JANBOUBI/PE_Parser/releases/download/v1.0/PE_Parser.zip) → download `PE_Parser.exe`

```powershell
# Basic info
PE_Parser.exe C:\Windows\System32\ntdll.dll

# Full verbose output (recommended)
PE_Parser.exe -v C:\Windows\System32\kernelbase.dll
```

### Build from Source

```bash
git clone https://github.com/yourusername/PE-Parser.git
cd PE-Parser
```

Open `PE-Parser.sln` in **Visual Studio 2022/2025** → Build → **Release | x64**

Or via command line:

```bash
msbuild PE-Parser.sln /p:Configuration=Release /p:Platform=x64
```

→ Executable: `Release\PE_Parser.exe`

## 🚀 Usage

```text
PE_Parser.exe [-v] <path_to_pe_file>

Options:
  -v, -V    Show full details (imports, exports, sections, directories)
  (no flag)        Compact mode (basic header info only)
```

### Examples

```powershell
PE_Parser.exe -V explorer.exe
PE_Parser.exe -V C:\Windows\System32\user32.dll
PE_Parser.exe -V suspicious_malware.sys
```

## Sample Outputs

| Mode        | Screenshot |
|------------|----------|
| Compact    |<img width="1039" height="699" alt="image" src="https://github.com/user-attachments/assets/3c18aad3-4448-4ef0-95e1-82e4661bf9ac" />|
| Verbose (Exports) | <img width="1022" height="700" alt="image" src="https://github.com/user-attachments/assets/1ccd5261-2e95-46d5-939d-a586bd27948f" />|
| Verbose (Imports) | <img width="1009" height="713" alt="image" src="https://github.com/user-attachments/assets/1dadf284-42e2-4c44-844c-f5dbb4c5898e" />|

---

## 📬 Contact

For questions, bug reports, contact me at [https://github.com/Y-JANBOUBI].

---

*Developed by Y. Janboubi.*  
*Version: 1.0*
