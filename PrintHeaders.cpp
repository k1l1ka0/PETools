#include "Global.h"

void PrintDosHeader(PIMAGE_DOS_HEADER pDosHeader)
{
	/*
	typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
	} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
	*/
	printf("Signature:\t\t%x\n", pDosHeader->e_magic);
	printf("Bytes on the last page of file:\t\t%x\n", pDosHeader->e_cblp);
	printf("Pages in file:\t\t%x\n", pDosHeader->e_cp);
	printf("Relocations:\t\t%x\n", pDosHeader->e_crlc);
	printf("Size of header in paragraphs:\t\t%x\n", pDosHeader->e_cparhdr);
	printf("Minimum extra paragraphs needed:\t\t%x\n", pDosHeader->e_minalloc);
	printf("Maximum extra paragraphs needed:\t\t%x\n", pDosHeader->e_maxalloc);
	printf("Initial ss:\t\t%x\n", pDosHeader->e_ss);
	printf("Initial sp:\t\t%x\n", pDosHeader->e_sp);
	printf("Checksum:\t\t%x\n", pDosHeader->e_csum);
	printf("Initial ip:\t\t%x\n", pDosHeader->e_ip);
	printf("Initial cs:\t\t%x\n", pDosHeader->e_cs);
	printf("File address of relocation table:\t\t%x\n", pDosHeader->e_lfarlc);
	printf("OEMID:\t\t%x\n", pDosHeader->e_oemid);
	printf("OEM Info:\t\t%x\n", pDosHeader->e_oeminfo);
	printf("File address of new exe header:\t\t%x\n", pDosHeader->e_lfanew);

}

void PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER32 pOptionalHeader)
{
	/*
	typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

		WORD    Magic;
		BYTE    MajorLinkerVersion;
		BYTE    MinorLinkerVersion;
		DWORD   SizeOfCode;
		DWORD   SizeOfInitializedData;
		DWORD   SizeOfUninitializedData;
		DWORD   AddressOfEntryPoint;
		DWORD   BaseOfCode;
		DWORD   BaseOfData;

		//
		// NT additional fields.
		//

		DWORD   ImageBase;
		DWORD   SectionAlignment;
		DWORD   FileAlignment;
		WORD    MajorOperatingSystemVersion;
		WORD    MinorOperatingSystemVersion;
		WORD    MajorImageVersion;
		WORD    MinorImageVersion;
		WORD    MajorSubsystemVersion;
		WORD    MinorSubsystemVersion;
		DWORD   Win32VersionValue;
		DWORD   SizeOfImage;
		DWORD   SizeOfHeaders;
		DWORD   CheckSum;
		WORD    Subsystem;
		WORD    DllCharacteristics;
		DWORD   SizeOfStackReserve;
		DWORD   SizeOfStackCommit;
		DWORD   SizeOfHeapReserve;
		DWORD   SizeOfHeapCommit;
		DWORD   LoaderFlags;
		DWORD   NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
*/
	printf("The state of the image file:\t\t%x\n", pOptionalHeader->Magic);
	printf("The major version number of the linker:\t\t%x\n", pOptionalHeader->MajorLinkerVersion);
	printf("The minor version number of the linker:\t\t%x\n", pOptionalHeader->MinorLinkerVersion);
	printf("The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections.:\t\t%x\n", pOptionalHeader->SizeOfCode);
	printf("The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections.:\t\t%x\n", pOptionalHeader->SizeOfInitializedData);
	printf("The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections.:\t\t%x\n", pOptionalHeader->SizeOfUninitializedData);
	printf("A pointer to the entry point function, relative to the image base address.For executable files, this is the starting address.For device drivers, this is the address of the initialization function.\
				The entry point function is optional for DLLs.When no entry point is present, this member is zero. : \t\t%x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("A pointer to the beginning of the code section, relative to the image base. :\t\t%x\n", pOptionalHeader->BaseOfCode);
	printf("A pointer to the beginning of the data section, relative to the image base. :\t\t%x\n", pOptionalHeader->BaseOfData);
	printf("The preferred address of the first byte of the image when it is loaded in memory. This value is a multiple of 64K bytes. \
				The default value for DLLs is 0x10000000. The default value for applications is 0x00400000, except on Windows CE where it is 0x00010000.\t\t%x\n", pOptionalHeader->ImageBase);
	printf("The alignment of sections loaded in memory, in bytes.This value must be greater than or equal to the FileAlignment member.\
				The default value is the page size for the system.\t\t%x\n",pOptionalHeader->SectionAlignment);
	printf("The alignment of the raw data of sections in the image file, in bytes. The value should be a power of 2 between 512 and 64K (inclusive). The default is 512. \
				If the SectionAlignment member is less than the system page size, this member must be the same as SectionAlignment.\t\t%x\n", pOptionalHeader->FileAlignment);
	printf("The major version number of the required operating system.\t\t%x\n", pOptionalHeader->MajorOperatingSystemVersion);
	printf("The minor version number of the required operating system.\t\t%x\n", pOptionalHeader->MinorOperatingSystemVersion);
	printf("The major version number of the image.\t\t%x\n", pOptionalHeader->MajorImageVersion);
	printf("The minor version number of the image.\t\t%x\n", pOptionalHeader->MinorImageVersion);
	printf("The major version number of the subsystem.\t\t%x\n", pOptionalHeader->MajorSubsystemVersion);
	printf("The minor version number of the subsystem.\t\t%x\n", pOptionalHeader->MinorSubsystemVersion);
	printf("Win32version value. This member is reserved and must be 0.\t\t%x\n", pOptionalHeader->Win32VersionValue);
	printf("The size of the image, in bytes, including all headers.Must be a multiple of SectionAlignment.\t\t%x\n", pOptionalHeader->SizeOfImage);
	printf("The size of headers.\t\t%x\n", pOptionalHeader->SizeOfHeaders);
	printf("The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time,\
			 and any DLL loaded into a critical system process.\t\t%x\n", pOptionalHeader->CheckSum);
	printf("Subsystem: \t\t%x\n", pOptionalHeader->Subsystem);
	printf("Dll Charistictics: \t\t%x\n", pOptionalHeader->DllCharacteristics);
	printf("SizeOfStackReserve: \t\t%x\n", pOptionalHeader->SizeOfStackReserve);
	printf("SizeOfStackCommit: \t\t%x\n", pOptionalHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve: \t\t%x\n", pOptionalHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommit: \t\t%x\n", pOptionalHeader->SizeOfHeapCommit);
	printf("The number of directory entries in the remainder of the optional header. Each entry describes a location and size.: \t\t%x\n", pOptionalHeader->NumberOfRvaAndSizes);
	
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader->DataDirectory;
	for (int i = 0;i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++, pDataDirectory++) {
		printf("Directory %d :\n", i);
		printf("Virtual Address:\t\t%x\n", pDataDirectory->VirtualAddress);
		printf("Size:\t\t%x\n", pDataDirectory->Size);
	}
}

void PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER64 pOptionalHeader)
{
	/*
	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
	*/
	printf("The state of the image file:\t\t%x\n", pOptionalHeader->Magic);
	printf("The major version number of the linker:\t\t%x\n", pOptionalHeader->MajorLinkerVersion);
	printf("The minor version number of the linker:\t\t%x\n", pOptionalHeader->MinorLinkerVersion);
	printf("The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections.:\t\t%x\n", pOptionalHeader->SizeOfCode);
	printf("The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections.:\t\t%x\n", pOptionalHeader->SizeOfInitializedData);
	printf("The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections.:\t\t%x\n", pOptionalHeader->SizeOfUninitializedData);
	printf("A pointer to the entry point function, relative to the image base address.For executable files, this is the starting address.For device drivers, this is the address of the initialization function.\
				The entry point function is optional for DLLs.When no entry point is present, this member is zero. : \t\t%x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("A pointer to the beginning of the code section, relative to the image base. :\t\t%x\n", pOptionalHeader->BaseOfCode);
	printf("The preferred address of the first byte of the image when it is loaded in memory. This value is a multiple of 64K bytes. \
				The default value for DLLs is 0x10000000. The default value for applications is 0x00400000, except on Windows CE where it is 0x00010000.\t\t%x\n", pOptionalHeader->ImageBase);
	printf("The alignment of sections loaded in memory, in bytes.This value must be greater than or equal to the FileAlignment member.\
				The default value is the page size for the system.\t\t%x\n", pOptionalHeader->SectionAlignment);
	printf("The alignment of the raw data of sections in the image file, in bytes. The value should be a power of 2 between 512 and 64K (inclusive). The default is 512. \
				If the SectionAlignment member is less than the system page size, this member must be the same as SectionAlignment.\t\t%x\n", pOptionalHeader->FileAlignment);
	printf("The major version number of the required operating system.\t\t%x\n", pOptionalHeader->MajorOperatingSystemVersion);
	printf("The minor version number of the required operating system.\t\t%x\n", pOptionalHeader->MinorOperatingSystemVersion);
	printf("The major version number of the image.\t\t%x\n", pOptionalHeader->MajorImageVersion);
	printf("The minor version number of the image.\t\t%x\n", pOptionalHeader->MinorImageVersion);
	printf("The major version number of the subsystem.\t\t%x\n", pOptionalHeader->MajorSubsystemVersion);
	printf("The minor version number of the subsystem.\t\t%x\n", pOptionalHeader->MinorSubsystemVersion);
	printf("Win32version value. This member is reserved and must be 0.\t\t%x\n", pOptionalHeader->Win32VersionValue);
	printf("The size of the image, in bytes, including all headers.Must be a multiple of SectionAlignment.\t\t%x\n", pOptionalHeader->SizeOfImage);
	printf("The size of headers.\t\t%x\n", pOptionalHeader->SizeOfHeaders);
	printf("The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time,\
			 and any DLL loaded into a critical system process.\t\t%x\n", pOptionalHeader->CheckSum);
	printf("Subsystem: \t\t%x\n", pOptionalHeader->Subsystem);
	printf("Dll Charistictics: \t\t%x\n", pOptionalHeader->DllCharacteristics);
	printf("SizeOfStackReserve: \t\t%x\n", pOptionalHeader->SizeOfStackReserve);
	printf("SizeOfStackCommit: \t\t%x\n", pOptionalHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve: \t\t%x\n", pOptionalHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommit: \t\t%x\n", pOptionalHeader->SizeOfHeapCommit);
	printf("The number of directory entries in the remainder of the optional header. Each entry describes a location and size.: \t\t%x\n", pOptionalHeader->NumberOfRvaAndSizes);
	//Data directories missed

	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader->DataDirectory;
	for (int i = 0;i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++, pDataDirectory++) {
		printf("Directory %d :\n", i);
		printf("Virtual Address:\t\t%x\n", pDataDirectory->VirtualAddress);
		printf("Size:\t\t%x\n", pDataDirectory->Size);
	}
}

void PrintSections(PIMAGE_SECTION_HEADER pSectionHeader, WORD n, LPVOID pFileBuffer)
{
	/*
	typedef struct _IMAGE_SECTION_HEADER {
		BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
		union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
		} Misc;
		DWORD VirtualAddress;
		DWORD SizeOfRawData;
		DWORD PointerToRawData;
		DWORD PointerToRelocations;
		DWORD PointerToLinenumbers;
		WORD  NumberOfRelocations;
		WORD  NumberOfLinenumbers;
		DWORD Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

	*/
	
	printf("Headers:\n");
	printf("Section Header Name\t\tVirtural Size\t\tVirtual Offset\t\tRaw Size\t\tRaw Offset\t\tCharacteristics\n");

	for (WORD i = 0; i < n; i++)
	{
		printf("%s\t\t", pSectionHeader[i].Name);
		printf("%8x\t\t", pSectionHeader[i].Misc.VirtualSize);
		printf("%8x\t\t", pSectionHeader[i].VirtualAddress);
		printf("%8x\t\t", pSectionHeader[i].SizeOfRawData);
		printf("%8x\t\t", pSectionHeader[i].PointerToRawData);
		printf("%8x\t\t\n\n\n", pSectionHeader[i].Characteristics);
	}
	//Dump Section Data to SectionDump.txt
	printf("Dumping Section Data to SectionDump.txt\n");

	char* SectionBuff = NULL;
	FILE* fp = NULL;
	if (!(fp = fopen("SectionDump.txt", "w"))) {
		printf("Create/Open file SectionDump.txt error!\n");
		return;
	}

	for (WORD i = 0;i < n;i++) {
		//printf("%s:\n", pSectionHeader[i].Name);
		
		char* sectionstart = (char*)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData);
		if (!(SectionBuff = (char*)malloc(pSectionHeader[i].SizeOfRawData))) {
			printf("mem allocation for section data failed!\n");
			return;
		}
		memcpy_s(SectionBuff, pSectionHeader[i].SizeOfRawData, sectionstart, pSectionHeader[i].SizeOfRawData);
		fprintf(fp, "\n\nSection %s:\n\n", pSectionHeader[i].Name);
		fwrite(SectionBuff, sizeof(char), pSectionHeader[i].SizeOfRawData, fp);
	}
	fclose(fp);
	printf("Dump section data done.\n");

}

int PrintHeaders(LPSTR lpFilename)
{	
	LPVOID pFileBuffer = NULL;
/*	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER sSections = NULL;
*/
	if (!(pFileBuffer = ReadPEFile(lpFilename)))
	{
		printf("Read file %s error!\n", lpFilename);
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {
		printf("Invalid MZ signature!\n");
		free(pFileBuffer);
		return 0;
	}

	//Print Dos Header;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	printf("*****************************************************************\n");
	printf("***************************Dos Headers***************************\n");
	PrintDosHeader(pDosHeader);
	printf("***************************Dos Headers ends**********************\n");
	printf("*****************************************************************\n\n");

	//Print the NT_Headers
/*
	typedef struct _IMAGE_NT_HEADERS {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
*/
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);

	printf("*****************************************************************\n");
	printf("***************************NT Headers****************************\n");
	printf("PE Signature:\t\t%x\n", pNTHeader->Signature);
	
	printf("***************************File Header***************************\n");
	/*
	typedef struct _IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
	*/
	
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew+4);
	printf("Machine:\t\t%x\n", pPEHeader->Machine);
	printf("*Number of Sections:\t\t%x\n", pPEHeader->NumberOfSections);
	printf("Time stamp:\t\t%x\n", pPEHeader->TimeDateStamp);
	printf("Pointer to symbol table:\t\t%x\n", pPEHeader->PointerToSymbolTable);
	printf("Number of symbols:\t\t%x\n", pPEHeader->NumberOfSymbols);
	printf("*Size of Optional Headers:\t\t%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("*The characteristics of the image:\t\t%x\n", pPEHeader->Characteristics);
	printf("***************************File Header ends**********************\n");
	printf("***************************Optional Header***********************\n");

	if (pPEHeader->Machine == 0x014c) {
		pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		PrintOptionalHeader(pOptionalHeader32);
	}
	else if (pPEHeader->Machine == 0x8664) {
		pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		PrintOptionalHeader(pOptionalHeader64);
	}


	printf("***************************Optional Header ends******************\n");
	printf("***************************NT Header ends************************\n\n");

	//section header

	if (!(sSections = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER)*pNTHeader->FileHeader.NumberOfSections))) {
		printf("Error allocation memory for Section Headers!\n");
		return 0;
	}
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections;i++)
		memcpy_s(&sSections[i], sizeof(IMAGE_SECTION_HEADER), (const void*)((DWORD)pSectionHeader + i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	
	printf("***************************Section Header************************\n");
	PrintSections(sSections, pNTHeader->FileHeader.NumberOfSections, pFileBuffer);
	printf("***************************Section Header ends*******************\n\n");

	return 1;
}

