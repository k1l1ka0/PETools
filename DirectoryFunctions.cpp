#include "Global.h"

VOID PrintExportTable(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
//		dwImageSize = pOptionalHeader32->SizeOfImage;
//		dwHeaderSize = pOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		//dwImageSize = pOptionalHeader64->SizeOfImage;
		//dwHeaderSize = pOptionalHeader64->SizeOfHeaders;
	}

	
	if (mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
		printf("Export Address Table empty!\n");
		return;
	}

	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
	printf("*************************Export Address Table********************\n");
	printf("DLL Name: %s\n", (PCHAR)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageExportDir->Name)));
	printf("Number of Functions: 0x%x\n", pImageExportDir->NumberOfFunctions);
	printf("-------------------------------------------------------------------------------\n");

	PDWORD pAddress = (PDWORD)(pImageExportDir->AddressOfFunctions);
	PDWORD pName = (PDWORD)(pImageExportDir->AddressOfNames);
	PWORD pOrdinal = (PWORD)(pImageExportDir->AddressOfNameOrdinals);
	printf(" Ordinal\thint\tRVA     \tName\n");
	for (int i = 0;i < pImageExportDir->NumberOfFunctions; i++) {
		printf("    %04X\t",pImageExportDir->Base + *(PWORD)((DWORD)pFileBuffer + (DWORD)RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pOrdinal + i))));
		
		DWORD fnRVA = *(PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pAddress + i)));
		printf("%04X\t%08X\t", i, fnRVA);

		DWORD fnNameRVA = *(PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pName + i)));
		printf("%s\n", (PCHAR)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, fnNameRVA)));
	}
}

DWORD SearchEATByName(IN LPVOID pFileBuffer, IN LPSTR FuncName)
{
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		//		dwImageSize = pOptionalHeader32->SizeOfImage;
		//		dwHeaderSize = pOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		//dwImageSize = pOptionalHeader64->SizeOfImage;
		//dwHeaderSize = pOptionalHeader64->SizeOfHeaders;
	}


	if (mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
		printf("Export Address Table empty.\n");
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
	PDWORD pAddress = (PDWORD)(pImageExportDir->AddressOfFunctions);
	PDWORD pName = (PDWORD)(pImageExportDir->AddressOfNames);
	PWORD pOrdinal = (PWORD)(pImageExportDir->AddressOfNameOrdinals);

	for (int i = 0;i < pImageExportDir->NumberOfFunctions; i++) {
		DWORD fnNameRVA = *(PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pName + i)));
		PCHAR fnName = (PCHAR)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, fnNameRVA));
		if (strcmp(fnName, FuncName)) {
			return (*(PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pAddress + i))));
		}	
	}

	printf("Cannot find Function %s in EAT.\n", FuncName);
	return 0;


}

DWORD SearchEATByOrdinal(IN LPVOID pFileBuffer, IN WORD Ordinal) {
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		//		dwImageSize = pOptionalHeader32->SizeOfImage;
		//		dwHeaderSize = pOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		//dwImageSize = pOptionalHeader64->SizeOfImage;
		//dwHeaderSize = pOptionalHeader64->SizeOfHeaders;
	}


	if (mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
		printf("Export Address Table empty!\n");
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
	PDWORD pAddress = (PDWORD)(pImageExportDir->AddressOfFunctions);
	PDWORD pName = (PDWORD)(pImageExportDir->AddressOfNames);
	PWORD pOrdinal = (PWORD)(pImageExportDir->AddressOfNameOrdinals);
	for (int i = 0;i < pImageExportDir->NumberOfFunctions; i++) {
		WORD mOrdinal = pImageExportDir->Base + *(PWORD)((DWORD)pFileBuffer + (DWORD)RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pOrdinal + i)));
		if (mOrdinal == Ordinal) {
			return *(PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, (DWORD)(pAddress + i)));
		}
	}
	return 0;
}

VOID PrintRelocationTable(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		//		dwImageSize = pOptionalHeader32->SizeOfImage;
		//		dwHeaderSize = pOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		//dwImageSize = pOptionalHeader64->SizeOfImage;
		//dwHeaderSize = pOptionalHeader64->SizeOfHeaders;
	}


	if (mpNTHeader->OptionalHeader.DataDirectory[5].VirtualAddress == 0) {
		printf("Relocation Address Table empty!\n");
		return;
	}

	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[5].VirtualAddress));
	while (pRelocation->VirtualAddress) {
		printf("%8X  RVA,\t %x size of blocks\n",pRelocation->VirtualAddress,pRelocation->SizeOfBlock);
		PWORD pRelAddr = (PWORD)((DWORD)pRelocation + 8);
		for (int i = 0;i < (pRelocation->SizeOfBlock-8)/2;i++) {
			WORD flag = *pRelAddr & 0x3000;
			WORD rem = *pRelAddr & 0x0FFF;
			if(flag)
				printf("%8X \tHIGHLOW\n",rem);
			else
				printf("%8X \tABSOLUTE\n", rem);
			pRelAddr++;
		}
		printf("======================================\n");
		pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocation + pRelocation->SizeOfBlock);
	}
}

VOID MoveEAT(IN LPVOID pFileBuffer, OUT LPSTR lpszFileName)
{
	LPVOID pNewBuffer;
	DWORD dwCopyAddr = InsertNewSection(pFileBuffer, 0x1000, &pNewBuffer);
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pNewBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pNewBuffer + mpDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNewBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
		printf("Empty EAT.\n");
		return;
	}
	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pNewBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
	DWORD dwOffset = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->VirtualAddress - (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->PointerToRawData;

	//Copy Address of Functions
	LPVOID lpfnRVA = (LPVOID)((DWORD)pNewBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageExportDir->AddressOfFunctions));
	memcpy_s((LPVOID)((DWORD)pNewBuffer+dwCopyAddr), 4 * pImageExportDir->NumberOfFunctions, lpfnRVA, 4 * pImageExportDir->NumberOfFunctions);
	DWORD newAddressOfFunctions = dwCopyAddr;
	dwCopyAddr += 4 * pImageExportDir->NumberOfFunctions;

	//Copy Address of Name ordinal
	LPVOID lpNameOrdinal = (LPVOID)((DWORD)pNewBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageExportDir->AddressOfNameOrdinals));
	memcpy_s((LPVOID)((DWORD)pNewBuffer + dwCopyAddr), 2 * pImageExportDir->NumberOfNames, lpNameOrdinal, 2 * pImageExportDir->NumberOfNames);
	DWORD newAddressOfNameOrdinals = dwCopyAddr;
	dwCopyAddr += 2 * pImageExportDir->NumberOfNames;

	//Copy Address of Names table
	DWORD StartOfNameTable = dwCopyAddr;
	PDWORD pStartOfNameTable = (PDWORD)((DWORD)pNewBuffer + StartOfNameTable);
	LPVOID lpfnNameRVA = (LPVOID)((DWORD)pNewBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageExportDir->AddressOfNames));
	memcpy_s((LPVOID)((DWORD)pNewBuffer + dwCopyAddr), 4 * pImageExportDir->NumberOfNames, lpfnNameRVA, 4 * pImageExportDir->NumberOfNames);
	DWORD newAddressOfNames = dwCopyAddr;
	dwCopyAddr += 4 * pImageExportDir->NumberOfNames;
	
	//Copy Names and repair nameRVA
	for (int i = 0;i < pImageExportDir->NumberOfNames;i++)
	{
		PCHAR dwName = (PCHAR)((DWORD)pNewBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, *(pStartOfNameTable + i)));
		memcpy_s((LPVOID)((DWORD)pNewBuffer + dwCopyAddr), strlen((PCHAR)dwName) + 1, (LPVOID)dwName, strlen((PCHAR)dwName) + 1);
		*(pStartOfNameTable + i) = dwCopyAddr + dwOffset;
		dwCopyAddr += strlen((PCHAR)dwName) + 1;
	}

	//Copy Image_export_directory
	DWORD newEATAddr = dwCopyAddr;
	memcpy_s((LPVOID)((DWORD)pNewBuffer + dwCopyAddr), sizeof(IMAGE_EXPORT_DIRECTORY), pImageExportDir, sizeof(IMAGE_EXPORT_DIRECTORY));
	PIMAGE_EXPORT_DIRECTORY pNewExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pNewBuffer + dwCopyAddr);

	//Repair export directory
	pNewExpDir->AddressOfFunctions = newAddressOfFunctions + dwOffset;
	pNewExpDir->AddressOfNameOrdinals = newAddressOfNameOrdinals + dwOffset;
	pNewExpDir->AddressOfNames = newAddressOfNames + dwOffset;

	//Repair Header EAT Address
	mpNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress = newEATAddr + dwOffset;

	//dump New file
	DWORD filesize = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->PointerToRawData + (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData;
	MemoryToFile(pNewBuffer, filesize, lpszFileName);
}

VOID PrintIAT(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		//		dwImageSize = pOptionalHeader32->SizeOfImage;
		//		dwHeaderSize = pOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		//dwImageSize = pOptionalHeader64->SizeOfImage;
		//dwHeaderSize = pOptionalHeader64->SizeOfHeaders;
	}
	
	if (mpNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress == 0) {
		printf("Import Address Table empty!\n");
		return;
	}
	DWORD dwIATFOA = RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + dwIATFOA);

	while (!(pImageImportDescriptor->Name == 0))
	{
		printf("\nDLL name: %s\n", (PCHAR)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageImportDescriptor->Name)));
		printf("==========Original First Thunk RVA================\n");
		PDWORD pOriginalFirstThunk = (PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageImportDescriptor->OriginalFirstThunk));
		printf("%x  -  %x\n", pOriginalFirstThunk, *pOriginalFirstThunk);
		printf("TimeDateStamp: %x\n", pImageImportDescriptor->TimeDateStamp);

		//Print INT
		while (*pOriginalFirstThunk) {
			if (*pOriginalFirstThunk&IMAGE_ORDINAL_FLAG32) {
				printf("Import by Ordinal: %x\n", (*pOriginalFirstThunk) & 0x0fff);
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, *pOriginalFirstThunk));
				printf("Import by Name Hint/Name:%x - %s\n", pImageByName->Hint, pImageByName->Name);
			}
			pOriginalFirstThunk = (PDWORD)((DWORD)pOriginalFirstThunk + sizeof(IMAGE_THUNK_DATA32));
		}

		//Print IAT
		PDWORD pFirstThunk = (PDWORD)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, pImageImportDescriptor->FirstThunk));
		printf("%x  -  %x\n", pFirstThunk, *pFirstThunk);
		printf("IAT Address from directory: %x \n", RvaToRaw(mpSectionHeader, mpNTHeader, mpNTHeader->OptionalHeader.DataDirectory[12].VirtualAddress));
		while (*pFirstThunk)
		{
			if (*pFirstThunk&IMAGE_ORDINAL_FLAG32) {
				printf("Import by Ordinal: %x\n", (*pFirstThunk) & 0x0fff);
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToRaw(mpSectionHeader, mpNTHeader, *pFirstThunk));
				printf("Import by Name Hint/Name:%x - %s\n", pImageByName->Hint, pImageByName->Name);
			}
			pFirstThunk = (PDWORD)((DWORD)pFirstThunk + sizeof(IMAGE_THUNK_DATA32));
		}
		pImageImportDescriptor++;
	}
}