#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <time.h>
#include <string.h>
#include <wincrypt.h>

#pragma execution_character_set("utf-8")
#pragma warning (disable:4996)


#define COLOR_RESET      "\033[38;5;250m"
#define COLOR_RED        "\033[38;2;232;0;0m"
#define COLOR_GREEN      "\033[38;2;0;200;0m"


typedef struct _IMPORTED_FUNC {
	char name[256];
	int  isOrdinal;
	WORD ordinal;
} IMPORTED_FUNC;

typedef struct _IMPORTED_LIB {
	char name[256];
	IMPORTED_FUNC* funcs;
	int funcCount;
} IMPORTED_LIB;



void print_logo() {
	system("cls");
	system("chcp 65001 > nul");
	system("title PE_Parser - by Y.JANBOUBI");
	printf("\n");
	printf("\033[38;2;0;150;0m");  // Green frame
	printf("╔═════════════════════════════════════════════════════════════════════════════════╗\n");
	printf("╚══════════════════════════════════[ PE_Parser ]══════════════════════════════════╝\n");
	printf("╚═════════════════════════════════════════════════════════════════════════════════╝\n");
	printf("      \033[38;2;0;200;0m ██████╗ ███████╗    ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗ \n");
	printf("      \033[38;2;0;220;0m ██╔══██╗██╔════╝    ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗\n");
	printf("      \033[38;2;0;240;0m ██████╔╝█████╗█████╗██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝\n");
	printf("      \033[38;2;80;255;80m ██╔═══╝ ██╔══╝╚════╝██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗\n");
	printf("      \033[38;2;120;255;120m ██║     ███████╗    ██║     ██║  ██║██║  ██║███████║███████╗██║  ██║\n");
	printf("      \033[38;2;150;255;150m ╚═╝     ╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝\n");
	printf("\033[38;2;0;150;0m");
	printf("╔═════════════════════════════════════════════════════════════════════════════════╗\n");
	printf("╚════════════════════════════════[ BY Y.JANBOUBI ]════════════════════════════════╝\n");
	printf("╚═════════════════════════════════════════════════════════════════════════════════╝\n\n");
	printf("\033[38;5;250m");
}
void print_help(char* arg0) {
	print_logo();
	printf("\033[38;2;0;150;0m");
	printf("[+] PE Types    : <EXE> <DLL> <SYS>\n");
	printf("[+] Verbos mode : -v or -V\n");
	printf("[+] Usage       : %s <PE file>\n", arg0);
	printf("[+] Examples    : %s -V PE_simple.exe\n", arg0);
	printf("\033[38;5;250m");
	getchar();
}


BOOL read_file(LPCSTR file_name, PBYTE* PE, SIZE_T* sPE) {

	DWORD  dwNumberOfBytesRead = 0;

	// open file  
	HANDLE hfile = CreateFileA(file_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// Get size of file 
	DWORD SPE = GetFileSize(hfile, NULL);

	// Allocated buffer 
	PBYTE  address = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SPE);

	// write file to allocated buffer 
	ReadFile(hfile, address, SPE, &dwNumberOfBytesRead, NULL);

	*PE = (PBYTE)address;
	*sPE = (SIZE_T)SPE;

	// cleanup 
	if (hfile)
		CloseHandle(hfile);
}
char* Get_Name(char* path) {
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];
	_splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
	static char result[_MAX_FNAME + _MAX_EXT];
	strcpy_s(result, sizeof(result), fname);
	strcat_s(result, sizeof(result), ext);
	return result;
}
void print_hash(BYTE* hash, DWORD hashLen) {
	for (DWORD i = 0; i < hashLen; i++)
		printf("%02X", hash[i]); // Uppercase
	printf("\n");
}
void hash_file(const char* filename) {
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE buffer[1024];
	DWORD bytesRead;
	FILE* file = fopen(filename, "rb");

	if (!file) {
		perror(COLOR_RED"[!] Failed to open file"COLOR_RESET);
		return;
	}

	// Initialize crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		fclose(file);
		return;
	}

	// --- MD5 ---
	if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
			CryptHashData(hHash, buffer, bytesRead, 0);
		}

		BYTE md5[16];
		DWORD md5Len = 16;
		CryptGetHashParam(hHash, HP_HASHVAL, md5, &md5Len, 0);

		printf("[+] ("COLOR_GREEN"MD5"COLOR_RESET"): ");
		print_hash(md5, md5Len);
		CryptDestroyHash(hHash);
	}

	// Reset file for SHA-256
	fseek(file, 0, SEEK_SET);

	// --- SHA-256 ---
	if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
			CryptHashData(hHash, buffer, bytesRead, 0);
		}

		BYTE sha256[32];
		DWORD sha256Len = 32;
		CryptGetHashParam(hHash, HP_HASHVAL, sha256, &sha256Len, 0);

		printf("[+] ("COLOR_GREEN"SHA-256"COLOR_RESET"): ");
		print_hash(sha256, sha256Len);
		CryptDestroyHash(hHash);
	}

	fclose(file);
	CryptReleaseContext(hProv, 0);
}
VOID ParseImports(PBYTE pPE, IMAGE_OPTIONAL_HEADER ImgOptHdr) {

	DWORD importRVA = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importSize = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	if (!importRVA || !importSize) {
		printf("\n[IMPORTS] No Import Directory.\n");
		return;
	}

	printf(COLOR_GREEN"\n[===================================[ IMPORTS ]===================================]\n"COLOR_RESET);

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)(pPE + importRVA);

	while (pImportDesc->Name != 0) {

		char* dllName = (char*)(pPE + pImportDesc->Name);
		printf("\n[+] DLL: " COLOR_GREEN "%s\n" COLOR_RESET, dllName);

		// Thunk arrays
		PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)(pPE + pImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)(pPE + pImportDesc->FirstThunk);

		while (thunkILT->u1.AddressOfData != 0) {

			// IMPORT BY ORDINAL?
			if (IMAGE_SNAP_BY_ORDINAL(thunkILT->u1.Ordinal)) {

				WORD ordinal = IMAGE_ORDINAL(thunkILT->u1.Ordinal);
				printf("\t-> Ordinal: %d\n", ordinal);

			}
			else {

				PIMAGE_IMPORT_BY_NAME pImportByName =
					(PIMAGE_IMPORT_BY_NAME)(pPE + thunkILT->u1.AddressOfData);

				printf("\t-> %s\n", pImportByName->Name);
			}

			thunkILT++;
			thunkIAT++;
		}

		pImportDesc++;
	}
}
VOID ParseExports(PBYTE pPE, IMAGE_OPTIONAL_HEADER ImgOptHdr) {

	DWORD exportRVA = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportSize = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!exportRVA || !exportSize) {
		printf("\n[EXPORTS] No Export Directory.\n");
		return;
	}

	printf(COLOR_GREEN"\n[===================================[ EXPORTS ]===================================]\n"COLOR_RESET);

	PIMAGE_EXPORT_DIRECTORY pExportDir =
		(PIMAGE_EXPORT_DIRECTORY)(pPE + exportRVA);

	DWORD* nameArray = (DWORD*)(pPE + pExportDir->AddressOfNames);
	DWORD* funcArray = (DWORD*)(pPE + pExportDir->AddressOfFunctions);
	WORD* ordinalArray = (WORD*)(pPE + pExportDir->AddressOfNameOrdinals);

	printf("[+] DLL Exports %d functions\n\n", pExportDir->NumberOfNames);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {

		char* funcName = (char*)(pPE + nameArray[i]);
		WORD ordinal = ordinalArray[i] + pExportDir->Base;

		DWORD funcRVA = funcArray[ordinalArray[i]];
		PVOID funcVA = (PVOID)(pPE + funcRVA);

		printf("    %s (Ordinal: %d, RVA: 0x%X)\n",
			funcName, ordinal, funcRVA);
	}
}
DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER pSectionHdr, int numSections) {
	for (int i = 0; i < numSections; i++, pSectionHdr++) {
		DWORD secVA = pSectionHdr->VirtualAddress;
		DWORD secSize = pSectionHdr->Misc.VirtualSize;
		if (rva >= secVA && rva < secVA + secSize)
			return rva - secVA + pSectionHdr->PointerToRawData;
	}
	return rva; // fallback, may be invalid
}
int CompareFunc(const void* a, const void* b) {
	IMPORTED_FUNC* fa = (IMPORTED_FUNC*)a;
	IMPORTED_FUNC* fb = (IMPORTED_FUNC*)b;
	return strcmp(fa->name, fb->name);
}


VOID print_Lib(INT Verb, int Type, int Lib_Count, IMPORTED_LIB* Fun_List)
{
	const char* header =
		(Type == 1)
		? "[==============================[EXPORTS - SUMMARY]==============================]"
		: "[==============================[IMPORTS - SUMMARY]==============================]";

	/* Validate type */
	if (Type != 1 && Type != 2)
		return;

	/* Sort functions if verbose */
	if (Verb == 1) {
		for (int i = 0; i < Lib_Count; i++) {
			qsort(
				Fun_List[i].funcs,
				Fun_List[i].funcCount,
				sizeof(IMPORTED_FUNC),
				CompareFunc
			);
		}
	}

	/* Print header */
	printf(COLOR_GREEN "%s\n\n" COLOR_RESET, header);

	/* Print libraries */
	for (int i = 0; i < Lib_Count; i++) {
		IMPORTED_LIB* lib = &Fun_List[i];

		printf("[+] Library: " COLOR_GREEN "%s" COLOR_RESET " (Functions: "COLOR_GREEN"%d"COLOR_RESET")\n",
			lib->name, lib->funcCount);

		/* Verbose: print functions */
		if (Verb == 1) {
			if (Type == 1) {  // Exports
				for (int j = 0; j < lib->funcCount; j++) {
					IMPORTED_FUNC* fn = &lib->funcs[j];
					printf("\t["COLOR_GREEN" #%d "COLOR_RESET"]  %s \n", fn->ordinal, fn->name);
				}
			}
			else {  // Imports
				for (int j = 0; j < lib->funcCount; j++) {
					IMPORTED_FUNC* fn = &lib->funcs[j];
					if (fn->isOrdinal)
						printf("\t[ORDINAL] "COLOR_GREEN"#%d\n"COLOR_RESET, fn->ordinal);
					else
						printf("\t[%d] "COLOR_GREEN"%s\n"COLOR_RESET, j + 1, fn->name);
				}
			}
		}

		printf("\n");
	}
}
VOID ParsePe(IN PBYTE pPE, IN char* Target_Name, IN char* Target_File_path, IN SIZE_T sPE, IN int Verb) {


	// 1_DOS_HEADER
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	// 2_NT_HEADERS
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdrs->FileHeader;
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;


	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE || pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {  // tchek with Magic number (MZ)
		printf("\n[+] FILE type: "COLOR_GREEN"Unknown File\n" COLOR_RESET);
		printf("[+] Reading FILE ["COLOR_RED"%s"COLOR_RESET"] of Size: "COLOR_RED"%d\n" COLOR_RESET, Target_Name, sPE);
		printf("[+] FILE Path: "COLOR_RED"%s\n" COLOR_RESET, Target_File_path);
		hash_file(Target_File_path);
		printf(COLOR_GREEN"[+] Please provide a valid PE file.\n"COLOR_RESET);
		printf(COLOR_RED"[-] Program terminated...\n\n"COLOR_RESET);

		return;
	}

	printf(COLOR_GREEN"\n[===================================[ PE_Info ]===================================]\n\n"COLOR_RESET);
	printf("[+] FILE type: "COLOR_GREEN"PE File"COLOR_RESET" (Valid DOS & NT Header)\n");
	printf("[+] Reading FILE ["COLOR_RED"%s"COLOR_RESET"] of Size: "COLOR_RED"%d\n" COLOR_RESET, Target_Name, sPE);
	printf("[+] FILE Path: "COLOR_RED"%s\n" COLOR_RESET, Target_File_path);
	hash_file(Target_File_path);




	printf(COLOR_GREEN"\n[=================================[ FILE HEADER ]=================================]\n"COLOR_RESET);

	// print executable type
	printf("[+] Executable Type: ");

	if (ImgFileHdr.Characteristics & IMAGE_FILE_DLL) {
		printf(COLOR_GREEN"DLL\n"COLOR_RESET);
	}
	else {
		// Check the subsystem from the Optional Header
		if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_NATIVE ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_NATIVE_WINDOWS) {
			printf(COLOR_GREEN"SYS (Driver)\n"COLOR_RESET);
		}
		else if (ImgFileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
			printf(COLOR_GREEN"EXE\n"COLOR_RESET);
		}
		else {
			printf(COLOR_RED "Unknown\n" COLOR_RESET);
		}
	}





	printf("[+] File Architecture: %s \n", ImgFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? COLOR_GREEN"x32"COLOR_RESET : COLOR_GREEN"x64"COLOR_RESET);
	printf("[+] Number Of Sections: "COLOR_GREEN"%d \n"COLOR_RESET, ImgFileHdr.NumberOfSections);
	printf("[+] Optional Header Size: "COLOR_GREEN"%d Byte \n"COLOR_RESET, ImgFileHdr.SizeOfOptionalHeader);

	// Convert TimeDateStamp to readable time
	time_t ts = ImgFileHdr.TimeDateStamp;
	struct tm timeinfo;
	char buffer[64];

	if (gmtime_s(&timeinfo, &ts) == 0) {
		strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
		printf("[i] TimeDateStamp: "COLOR_GREEN"%s (UTC)\n"COLOR_RESET, buffer);
	}
	else {
		printf("[i] TimeDateStamp: "COLOR_GREEN"Invalid timestamp\n"COLOR_RESET);
	}

	printf(COLOR_GREEN"\n[===============================[ OPTIONAL HEADER ]===============================]\n"COLOR_RESET);


	// 4_NT_HEADERS->OPTIONAL_HEADER
	if (pImgNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		PIMAGE_NT_HEADERS32	 pImgNtHdrs32 = (PIMAGE_NT_HEADERS32)(pPE + pImgDosHdr->e_lfanew);
		IMAGE_OPTIONAL_HEADER32 ImgOptHdr = pImgNtHdrs32->OptionalHeader;

		printf("[+] File Arch (Second way): ("COLOR_GREEN"32-bit"COLOR_RESET")\n");
		printf("[+] Linker Version: "COLOR_GREEN"%d.%d \n"COLOR_RESET, ImgOptHdr.MajorLinkerVersion, ImgOptHdr.MinorLinkerVersion);
		//section size
		printf("[+] Size Of Code Section (.text) : "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfCode);
		printf("[+] Size Of Initialized Data (.data): "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfInitializedData);
		printf("[+] Size Of Uninitialized Data (.bss): "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfUninitializedData);

		//address 
		printf("[+] Address Of Image_Base: [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%p"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.ImageBase), ImgOptHdr.ImageBase);
		printf("[+] Address Of Entry_Point: [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%0.8X"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.AddressOfEntryPoint), ImgOptHdr.AddressOfEntryPoint);
		printf("[+] Address Of Base_of_Code (.text): [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%0.8X"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.BaseOfCode), ImgOptHdr.BaseOfCode);
		printf("[+] Address Of Base_of_Data (.data "COLOR_GREEN"32-Only"COLOR_RESET"): [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%0.8X"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.BaseOfData), ImgOptHdr.BaseOfData);


		printf("[+] OS Required Version: "COLOR_GREEN"%d.%d \n"COLOR_RESET, ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
		printf("[+] Image Version: "COLOR_GREEN"%d.%d \n"COLOR_RESET, ImgOptHdr.MajorImageVersion, ImgOptHdr.MinorImageVersion);
		// cheek the subsystem Type  
		const char* subsystemType;
		if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_NATIVE ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_NATIVE_WINDOWS ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
			subsystemType = "Driver";
		}
		else if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
			subsystemType = "GUI";
		}
		else if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
			subsystemType = "CLI";
		}
		else {
			subsystemType = "Unknown";
		}

		printf("[+] Subsystem Version: " COLOR_GREEN "%d.%d (%s)\n"COLOR_RESET, ImgOptHdr.MajorSubsystemVersion, ImgOptHdr.MinorSubsystemVersion, subsystemType);

		printf("[+] Size Of The Image: "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfImage);
		printf("[+] File CheckSum: "COLOR_GREEN"0x%0.8X \n"COLOR_RESET, ImgOptHdr.CheckSum);
		printf("[+] Number of entries in the DataDirectory array: "COLOR_GREEN"%u \n"COLOR_RESET, ImgOptHdr.NumberOfRvaAndSizes);

		// 5_OPTIONAL_HEADER->DATA_DIRECTORY
		printf(COLOR_GREEN"\n[=================================[ DIRECTORIES ]=================================]\n"COLOR_RESET);
#define PRINT_DIRECTORY(name, dirIndex) \
		do { \
			if (ImgOptHdr.DataDirectory[dirIndex].Size == 0 || ImgOptHdr.DataDirectory[dirIndex].VirtualAddress == 0) { \
				printf("[+] " name " Directory: [Size:" COLOR_GREEN "0 => Empty" COLOR_RESET "]\n"); \
			} else { \
				printf("[+] " name " Directory [VA:" COLOR_GREEN "0x%p" COLOR_RESET "] [Size:" COLOR_GREEN "%u" COLOR_RESET "] [RVA:" COLOR_GREEN "0x%08X" COLOR_RESET "]\n", \
					(PVOID)((BYTE*)pPE + ImgOptHdr.DataDirectory[dirIndex].VirtualAddress), \
					ImgOptHdr.DataDirectory[dirIndex].Size, \
					ImgOptHdr.DataDirectory[dirIndex].VirtualAddress); \
			} \
		} while(0)

		PRINT_DIRECTORY("Export", IMAGE_DIRECTORY_ENTRY_EXPORT);
		PRINT_DIRECTORY("Import", IMAGE_DIRECTORY_ENTRY_IMPORT);
		PRINT_DIRECTORY("Resource", IMAGE_DIRECTORY_ENTRY_RESOURCE);
		PRINT_DIRECTORY("Exception", IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		PRINT_DIRECTORY("Base Relocation", IMAGE_DIRECTORY_ENTRY_BASERELOC);
		PRINT_DIRECTORY("TLS", IMAGE_DIRECTORY_ENTRY_TLS);
		PRINT_DIRECTORY("Import Address Table", IMAGE_DIRECTORY_ENTRY_IAT);



		// section 
		printf(COLOR_GREEN"\n[==================================[ .SECTIONS ]==================================]\n"COLOR_RESET);

		PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS32));

		for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
			printf("[+] [Section " COLOR_GREEN "%s" COLOR_RESET "]\n", (CHAR*)pImgSectionHdr->Name);
			printf("\t[+] Raw Size : " COLOR_GREEN "%d" COLOR_RESET "\n", pImgSectionHdr->SizeOfRawData);
			printf("\t[+] Virtual Size : " COLOR_GREEN "%d" COLOR_RESET "\n", pImgSectionHdr->Misc.VirtualSize);
			printf("\t[+] Address & RVA : [VA " COLOR_GREEN "0x%p" COLOR_RESET "]  ", (PVOID)(pPE + pImgSectionHdr->VirtualAddress));
			printf("[RVA : " COLOR_GREEN "0x%0.8X" COLOR_RESET "]\n", pImgSectionHdr->VirtualAddress);
			printf("\t[+] Relocations : " COLOR_GREEN "%d" COLOR_RESET "\n", pImgSectionHdr->NumberOfRelocations);
			printf("\t[+] Permissions : ");

			if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE))
				printf(COLOR_RED"PAGE_EXECUTE_READWRITE"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ))
				printf(COLOR_GREEN"PAGE_EXECUTE_READ"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE))
				printf(COLOR_GREEN"PAGE_EXECUTE"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE))
				printf(COLOR_GREEN"PAGE_READWRITE"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ))
				printf(COLOR_GREEN"PAGE_READONLY"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE))
				printf(COLOR_GREEN"PAGE_WRITECOPY"COLOR_RESET);
			else
				printf(COLOR_GREEN"PAGE_NOACCESS"COLOR_RESET);

			printf("\n\n");
			pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + sizeof(IMAGE_SECTION_HEADER));
		}



		// ========================= EXPORT SUMMARY =========================
		IMPORTED_LIB* ExportList = NULL;
		int ExportLibCount = 0;
		if (ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0) {

			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
				pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
				);

			// Create a single "Export Library" entry
			ExportList = realloc(ExportList, sizeof(IMPORTED_LIB) * (ExportLibCount + 1));
			IMPORTED_LIB* lib = &ExportList[ExportLibCount];
			ZeroMemory(lib, sizeof(IMPORTED_LIB));
			strcpy(lib->name, "Exports");  // Generic library name
			lib->funcs = NULL;
			lib->funcCount = 0;

			DWORD* nameRVAs = (DWORD*)(pPE + pExportDir->AddressOfNames);
			WORD* ordinals = (WORD*)(pPE + pExportDir->AddressOfNameOrdinals);

			for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
				DWORD nameRVA = nameRVAs[i];
				DWORD nameOffset = RvaToOffset(nameRVA, (PIMAGE_SECTION_HEADER)((BYTE*)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS32)), pImgNtHdrs->FileHeader.NumberOfSections);

				// Add new function
				lib->funcs = realloc(lib->funcs, sizeof(IMPORTED_FUNC) * (lib->funcCount + 1));
				IMPORTED_FUNC* fn = &lib->funcs[lib->funcCount];
				ZeroMemory(fn, sizeof(IMPORTED_FUNC));
				fn->isOrdinal = 0;  // Exported functions have names
				strcpy(fn->name, (char*)(pPE + nameOffset));
				fn->ordinal = ordinals[i];  // Store ordinal for reference
				lib->funcCount++;
			}

			ExportLibCount++;
			print_Lib(Verb, 1, ExportLibCount, ExportList);
		}
		else {
			printf(COLOR_GREEN"[+] No Export Table found.\n"COLOR_RESET);
		}

		// ========================= IMPORT SUMMARY =========================
		IMPORTED_LIB* ImportList = NULL;
		int ImportLibCount = 0;
		if (ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {

			PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)((BYTE*)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS32));

			DWORD importRVA = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			DWORD importOffset = RvaToOffset(importRVA, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);

			PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPE + importOffset);

			while (pImportDesc->Name) {

				// Allocate new library entry
				ImportList = realloc(ImportList, sizeof(IMPORTED_LIB) * (ImportLibCount + 1));
				IMPORTED_LIB* lib = &ImportList[ImportLibCount];
				ZeroMemory(lib, sizeof(IMPORTED_LIB));

				// Store library name
				DWORD nameOffset = RvaToOffset(pImportDesc->Name, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);
				strcpy(lib->name, (char*)(pPE + nameOffset));

				lib->funcs = NULL;
				lib->funcCount = 0;

				DWORD thunkRVA = pImportDesc->OriginalFirstThunk
					? pImportDesc->OriginalFirstThunk
					: pImportDesc->FirstThunk;

				DWORD thunkOffset = RvaToOffset(thunkRVA, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);
				PBYTE thunkBase = pPE + thunkOffset;

				while (1) {
					ULONGLONG thunkVal = *(ULONGLONG*)thunkBase;
					if (!thunkVal)
						break;

					// Resize function list
					lib->funcs = realloc(lib->funcs, sizeof(IMPORTED_FUNC) * (lib->funcCount + 1));
					IMPORTED_FUNC* fn = &lib->funcs[lib->funcCount];
					ZeroMemory(fn, sizeof(IMPORTED_FUNC));

					// Ordinal import
					if (thunkVal & IMAGE_ORDINAL_FLAG64) {
						fn->isOrdinal = 1;
						fn->ordinal = (WORD)(thunkVal & 0xFFFF);
					}
					else {
						DWORD funcOffset = RvaToOffset((DWORD)thunkVal, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pPE + funcOffset);
						fn->isOrdinal = 0;
						strcpy(fn->name, pName->Name);
					}
					lib->funcCount++;
					thunkBase += sizeof(ULONGLONG);
				}
				ImportLibCount++;
				pImportDesc++;
			}

			print_Lib(Verb, 2, ImportLibCount, ImportList);

		}
		else {
			printf(COLOR_GREEN"\n[+] No Import Table found.\n\n"COLOR_RESET);
		}


	}
	else if (pImgNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

		IMAGE_OPTIONAL_HEADER64 ImgOptHdr = pImgNtHdrs->OptionalHeader;

		printf("[+] File Arch (Second way): ("COLOR_GREEN"64-bit"COLOR_RESET")\n");
		printf("[+] Linker Version: "COLOR_GREEN"%d.%d \n"COLOR_RESET, ImgOptHdr.MajorLinkerVersion, ImgOptHdr.MinorLinkerVersion);
		//section size
		printf("[+] Size Of Code Section (.text) : "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfCode);
		printf("[+] Size Of Initialized Data (.data): "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfInitializedData);
		printf("[+] Size Of Uninitialized Data (.bss): "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfUninitializedData);

		//address 
		printf("[+] Address Of Image_Base: [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%p"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.ImageBase), ImgOptHdr.ImageBase);
		printf("[+] Address Of Entry_Point: [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%0.8X"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.AddressOfEntryPoint), ImgOptHdr.AddressOfEntryPoint);
		printf("[+] Address Of Base_of_Code (.text): [VA:"COLOR_GREEN"0x%p"COLOR_RESET"]  [RVA:"COLOR_GREEN"0x%0.8X"COLOR_RESET"]\n", (PVOID)(pPE + ImgOptHdr.BaseOfCode), ImgOptHdr.BaseOfCode);

		// Vr
		printf("[+] OS Required Version: "COLOR_GREEN"%d.%d \n"COLOR_RESET, ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
		printf("[+] Image Version: "COLOR_GREEN"%d.%d \n"COLOR_RESET, ImgOptHdr.MajorImageVersion, ImgOptHdr.MinorImageVersion);


		// cheek the subsystem Type  
		const char* subsystemType;
		if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_NATIVE ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_NATIVE_WINDOWS ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER ||
			ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
			subsystemType = "Driver";
		}
		else if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
			subsystemType = "GUI";
		}
		else if (ImgOptHdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
			subsystemType = "CLI";
		}
		else {
			subsystemType = "Unknown";
		}


		printf("[+] Subsystem Version: " COLOR_GREEN "%d.%d (%s)\n"COLOR_RESET, ImgOptHdr.MajorSubsystemVersion, ImgOptHdr.MinorSubsystemVersion, subsystemType);
		printf("[+] Size Of The Image: "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.SizeOfImage);
		printf("[+] File CheckSum: "COLOR_GREEN"0x%0.8X \n"COLOR_RESET, ImgOptHdr.CheckSum);
		printf("[+] Number of entries in the DataDirectory array: "COLOR_GREEN"%d \n"COLOR_RESET, ImgOptHdr.NumberOfRvaAndSizes);


		// 5_OPTIONAL_HEADER->DATA_DIRECTORY
		printf(COLOR_GREEN"\n[=================================[ DIRECTORIES ]=================================]\n"COLOR_RESET);

#define PRINT_DIRECTORY(name, dirIndex) \
		do { \
			if (ImgOptHdr.DataDirectory[dirIndex].Size == 0 || ImgOptHdr.DataDirectory[dirIndex].VirtualAddress == 0) { \
				printf("[+] " name " Directory: [Size:" COLOR_GREEN "0 => Empty" COLOR_RESET "]\n"); \
			} else { \
				printf("[+] " name " Directory [VA:" COLOR_GREEN "0x%p" COLOR_RESET "] [Size:" COLOR_GREEN "%u" COLOR_RESET "] [RVA:" COLOR_GREEN "0x%08X" COLOR_RESET "]\n", \
					(PVOID)((BYTE*)pPE + ImgOptHdr.DataDirectory[dirIndex].VirtualAddress), \
					ImgOptHdr.DataDirectory[dirIndex].Size, \
					ImgOptHdr.DataDirectory[dirIndex].VirtualAddress); \
			} \
		} while(0)

		PRINT_DIRECTORY("Export", IMAGE_DIRECTORY_ENTRY_EXPORT);
		PRINT_DIRECTORY("Import", IMAGE_DIRECTORY_ENTRY_IMPORT);
		PRINT_DIRECTORY("Resource", IMAGE_DIRECTORY_ENTRY_RESOURCE);
		PRINT_DIRECTORY("Exception", IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		PRINT_DIRECTORY("Base Relocation", IMAGE_DIRECTORY_ENTRY_BASERELOC);
		PRINT_DIRECTORY("TLS", IMAGE_DIRECTORY_ENTRY_TLS);
		PRINT_DIRECTORY("Import Address Table", IMAGE_DIRECTORY_ENTRY_IAT);


		// section 
		printf(COLOR_GREEN"\n[==================================[ .SECTIONS ]==================================]\n"COLOR_RESET);

		PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS64));

		for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
			printf("[+] [Section " COLOR_GREEN "%s" COLOR_RESET "]\n", (CHAR*)pImgSectionHdr->Name);
			printf("\t[+] Raw Size : " COLOR_GREEN "%d" COLOR_RESET "\n", pImgSectionHdr->SizeOfRawData);
			printf("\t[+] Virtual Size : " COLOR_GREEN "%d" COLOR_RESET "\n", pImgSectionHdr->Misc.VirtualSize);
			printf("\t[+] Address & RVA : [VA " COLOR_GREEN "0x%p" COLOR_RESET "]  ", (PVOID)(pPE + pImgSectionHdr->VirtualAddress));
			printf("[RVA : " COLOR_GREEN "0x%0.8X" COLOR_RESET "]\n", pImgSectionHdr->VirtualAddress);
			printf("\t[+] Relocations : " COLOR_GREEN "%d" COLOR_RESET "\n", pImgSectionHdr->NumberOfRelocations);
			printf("\t[+] Permissions : ");

			if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE))
				printf(COLOR_RED"PAGE_EXECUTE_READWRITE"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ))
				printf(COLOR_GREEN"PAGE_EXECUTE_READ"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE))
				printf(COLOR_GREEN"PAGE_EXECUTE"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE))
				printf(COLOR_GREEN"PAGE_READWRITE"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ))
				printf(COLOR_GREEN"PAGE_READONLY"COLOR_RESET);
			else if ((pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE))
				printf(COLOR_GREEN"PAGE_WRITECOPY"COLOR_RESET);
			else
				printf(COLOR_GREEN"PAGE_NOACCESS"COLOR_RESET);

			printf("\n\n");
			pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + sizeof(IMAGE_SECTION_HEADER));
		}


		// ========================= EXPORT SUMMARY =========================
		IMPORTED_LIB* ExportList = NULL;
		int ExportLibCount = 0;
		if (ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0) {

			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
				pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
				);

			// Create a single "Export Library" entry
			ExportList = realloc(ExportList, sizeof(IMPORTED_LIB) * (ExportLibCount + 1));
			IMPORTED_LIB* lib = &ExportList[ExportLibCount];
			ZeroMemory(lib, sizeof(IMPORTED_LIB));
			strcpy(lib->name, "Exports");  // Generic library name
			lib->funcs = NULL;
			lib->funcCount = 0;

			DWORD* nameRVAs = (DWORD*)(pPE + pExportDir->AddressOfNames);
			WORD* ordinals = (WORD*)(pPE + pExportDir->AddressOfNameOrdinals);

			for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
				DWORD nameRVA = nameRVAs[i];
				DWORD nameOffset = RvaToOffset(nameRVA, (PIMAGE_SECTION_HEADER)((BYTE*)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS64)), pImgNtHdrs->FileHeader.NumberOfSections);

				// Add new function
				lib->funcs = realloc(lib->funcs, sizeof(IMPORTED_FUNC) * (lib->funcCount + 1));
				IMPORTED_FUNC* fn = &lib->funcs[lib->funcCount];
				ZeroMemory(fn, sizeof(IMPORTED_FUNC));
				fn->isOrdinal = 0;  // Exported functions have names
				strcpy(fn->name, (char*)(pPE + nameOffset));
				fn->ordinal = ordinals[i];  // Store ordinal for reference

				lib->funcCount++;
			}

			ExportLibCount++;
			print_Lib(Verb, 1, ExportLibCount, ExportList);
		}
		else {
			printf(COLOR_GREEN"[+] No Export Table found.\n"COLOR_RESET);
		}

		// ========================= IMPORT SUMMARY =========================
		IMPORTED_LIB* ImportList = NULL;
		int ImportLibCount = 0;
		if (ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {

			PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)((BYTE*)pImgNtHdrs + sizeof(IMAGE_NT_HEADERS64));

			DWORD importRVA = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			DWORD importOffset = RvaToOffset(importRVA, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);

			PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPE + importOffset);

			while (pImportDesc->Name) {

				// Allocate new library entry
				ImportList = realloc(ImportList, sizeof(IMPORTED_LIB) * (ImportLibCount + 1));
				IMPORTED_LIB* lib = &ImportList[ImportLibCount];
				ZeroMemory(lib, sizeof(IMPORTED_LIB));

				// Store library name
				DWORD nameOffset = RvaToOffset(pImportDesc->Name, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);
				strcpy(lib->name, (char*)(pPE + nameOffset));

				lib->funcs = NULL;
				lib->funcCount = 0;

				DWORD thunkRVA = pImportDesc->OriginalFirstThunk
					? pImportDesc->OriginalFirstThunk
					: pImportDesc->FirstThunk;

				DWORD thunkOffset = RvaToOffset(thunkRVA, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);
				PBYTE thunkBase = pPE + thunkOffset;

				while (1) {
					ULONGLONG thunkVal = *(ULONGLONG*)thunkBase;
					if (!thunkVal)
						break;

					// Resize function list
					lib->funcs = realloc(lib->funcs, sizeof(IMPORTED_FUNC) * (lib->funcCount + 1));
					IMPORTED_FUNC* fn = &lib->funcs[lib->funcCount];
					ZeroMemory(fn, sizeof(IMPORTED_FUNC));

					// Ordinal import
					if (thunkVal & IMAGE_ORDINAL_FLAG64) {
						fn->isOrdinal = 1;
						fn->ordinal = (WORD)(thunkVal & 0xFFFF);
					}
					else {
						DWORD funcOffset = RvaToOffset((DWORD)thunkVal, pSectionHdr, pImgNtHdrs->FileHeader.NumberOfSections);
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pPE + funcOffset);
						fn->isOrdinal = 0;
						strcpy(fn->name, pName->Name);
					}
					lib->funcCount++;
					thunkBase += sizeof(ULONGLONG);
				}
				ImportLibCount++;
				pImportDesc++;
			}

			print_Lib(Verb, 2, ImportLibCount, ImportList);

		}
		else {

			printf(COLOR_GREEN"\n[+] No Import Table found.\n\n"COLOR_RESET);
		}


	}
	else {
		printf(COLOR_RED"[+] Unknown OPTIONAL_HEADER magic\n"COLOR_RESET);
	}




}


int main(int argc, char* argv[]) {
	system("chcp 65001 > nul");

	char* PE_Parser = Get_Name(argv[0]);
	int verbose = 0;
	char* pe_file = NULL;

	PBYTE pPE = NULL;
	SIZE_T sPE = 0;

	// Validate argument count first
	if (argc < 2) {
		print_logo();
		printf("\033[38;2;0;150;0m");
		printf("[!] Invalid arguments\n");
		printf("[!] For help: %s -h or --help\n", PE_Parser);
		printf("\033[38;5;250m");
		getchar();
		return 1;
	}

	// Parse arguments with a loop
	for (int i = 1; i < argc; i++) {
		if (argc == 2 && (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)) {
			print_help(PE_Parser);
			return 0;
		}
		else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-V") == 0) {
			verbose = 1;
		}
		else if (pe_file == NULL) {
			pe_file = argv[i];
		}
		else {
			// More than one non-option argument
			printf("\033[38;2;0;150;0m");
			printf("[!] Invalid arguments\n");
			printf("[!] For help: %s -h or --help\n", PE_Parser);
			printf("\033[38;5;250m");
			return 1;
		}
	}

	// Check if PE file was provided
	if (pe_file == NULL) {
		printf("\033[38;2;0;150;0m");
		printf("[!] Missing PE file\n");
		printf("[!] For help: %s -h or --help\n", PE_Parser);
		printf("\033[38;5;250m");
		return 1;
	}

	// Read the PE file
	if (!read_file(pe_file, &pPE, &sPE)) {
		printf("\033[38;2;0;150;0m");
		printf("[!] Failed to read file: %s\n", pe_file);
		printf("\033[38;5;250m");
		return -1;
	}

	char full_path[MAX_PATH] = { 0 };
	GetFullPathNameA(pe_file, MAX_PATH, full_path, NULL);
	char* Target_PE = Get_Name(pe_file);

	// Parse the PE file
	ParsePe(pPE, Target_PE, full_path, sPE, verbose);

	HeapFree(GetProcessHeap(), 0, pPE);
	return 0;
}