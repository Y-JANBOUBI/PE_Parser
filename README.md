
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


## ✨ Features

### **Header Parsing**

* DOS & NT verification
* File header extraction
* Optional header parsing (PE32/PE32+)
* Hashes (MD5 / SHA-256)
* Timestamps (converted to UTC)

### **Directory Extraction**

* Export table
* Import table
* Resource directory
* Exception directory
* Base relocation table
* TLS data
* IAT directory
* CLR header (when present)

### **Section Insights**

* Section names, raw/virtual sizes
* RVA vs RAW mapping
* Characteristics & permissions

### **Import Summary**

* Library-by-library breakdown
* Function count
* Ordinal and name resolution


## Quick Start

### Download Latest Release (Recommended)

Go to [Releases](https://github.com/yourusername/PE-Parser/releases/latest) → download `PE_Parser.exe`

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

## Usage

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
| Compact    | <img src="https://raw.githubusercontent.com/yourusername/PE-Parser/main/screenshots/compact.jpg" width="600"/> |
| Verbose (Imports) | <img src="https://raw.githubusercontent.com/yourusername/PE-Parser/main/screenshots/imports.jpg" width="600"/> |
| Verbose (Exports) | <img src="https://raw.githubusercontent.com/yourusername/PE-Parser/main/screenshots/exports.jpg" width="600"/> |





Below is a **fully polished, professional, production-ready GitHub README.md** designed specifically for your **PE-Parser** project and the screenshots you provided.

This is the kind of README used in mature security/reversing tools — clean, structured, and highly informative.

You can copy/paste this directly into `README.md` and push to GitHub.

---

# **PE-Parser**

A high-performance Windows Portable Executable (PE) analysis tool for EXE, DLL, and SYS binaries — built for malware analysts, reverse engineers, and digital forensics professionals.

<p align="center">
  <img src="docs/screenshots/peparser_main.png" width="750">
</p>

---

## 🔍 Project Overview

**PE-Parser** is a lightweight and fast command-line utility that analyzes the structure of Windows Portable Executable (PE) files.
It extracts detailed information from PE headers, directories, and sections, and provides comprehensive insight into dependencies, imports, and metadata.

The tool is ideal for:

* Malware analysis
* Binary inspection
* Windows internal research
* Reverse engineering education
* Static analysis pipelines

---

## ✨ Features

### **Header Parsing**

* DOS & NT verification
* File header extraction
* Optional header parsing (PE32/PE32+)
* Hashes (MD5 / SHA-256)
* Timestamps (converted to UTC)

### **Directory Extraction**

* Export table
* Import table
* Resource directory
* Exception directory
* Base relocation table
* TLS data
* IAT directory
* CLR header (when present)

### **Section Insights**

* Section names, raw/virtual sizes
* RVA vs RAW mapping
* Characteristics & permissions

### **Import Summary**

* Library-by-library breakdown
* Function count
* Ordinal and name resolution

<p align="center">
  <img src="docs/screenshots/peparser_imports.png" width="750">
</p>

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

## 🚀 Usage

### **Basic Syntax**

```sh
PE_Parser.exe <PE_File>
```

### **Verbose Mode**

```sh
PE_Parser.exe -v <PE_File>
```

### **Examples**

```sh
PE_Parser.exe .\notepad.exe
PE_Parser.exe -v .\KernelBase.dll
```

---

## 🛠️ Build Instructions

### **MSVC (Windows)**

```sh
cl /EHsc /O2 /FePE_Parser.exe src\pe_parser.cpp
```

### **MinGW**

```sh
g++ src/pe_parser.cpp -O2 -o PE_Parser.exe
```

*(Adjust paths and filenames to match your repository.)*

---

## 📂 Repository Structure

```
PE-Parser/
│
├── src/
│   ├── pe_parser.cpp
│   └── pe_structs.h
│
├── docs/
│   └── screenshots/
│       ├── peparser_main.png
│       ├── peparser_sections.png
│       └── peparser_imports.png
│
├── LICENSE
└── README.md
```

---

## 📥 Downloads

Precompiled binaries will be available in the **Releases** section:

👉 [https://github.com/](https://github.com/)<your-username>/PE-Parser/releases

---

## 🤝 Contributing

Contributions are welcome!
Whether you're fixing bugs, adding features, or improving documentation:

1. Fork the repo
2. Create a feature branch
3. Commit your changes
4. Open a pull request

---

## ⭐ Support

If you find this tool useful, please consider giving the repository a **star** — it helps the project grow and supports future updates.

---

## 📜 License

This project is licensed under the **MIT License**.
See the `LICENSE` file for more details.

---

If you'd like, I can also generate:

✅ A professional **logo/banner**
✅ A **Dark mode** screenshot montage
✅ A full **CHANGELOG.md**
✅ GitHub Actions CI (Windows build pipeline)
✅ A **man page** or **wiki documentation**

Just tell me!

