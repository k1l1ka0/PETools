#include "Global.h"


PIMAGE_DOS_HEADER pDosHeader = NULL;
PIMAGE_NT_HEADERS pNTHeader = NULL;
PIMAGE_FILE_HEADER pPEHeader = NULL;
PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = NULL;
PIMAGE_SECTION_HEADER pSectionHeader = NULL;
PIMAGE_SECTION_HEADER sSections = NULL;
DWORD dwImageSize = 0;
DWORD dwHeaderSize = 0;



BYTE  shellcode[] =
{
	0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
	0xE8, 0x00, 0x00, 0x00, 0x00,
	0xE9, 0x00, 0x00, 0x00, 0x00
};

LPVOID ReadPEFile(LPSTR lpszFilename)
{
	DWORD size = 0;
	FILE* pFile = NULL;
	LPVOID pFileBuffer = NULL;
	size_t result;

	pFile = fopen(lpszFilename, "rb");
	if (pFile == NULL) {
		printf("Cannot open file!\n");
		return NULL;
	}
	fseek(pFile, 0, SEEK_END);
	size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	pFileBuffer = (char*)malloc(size * sizeof(char));
	if (pFileBuffer == NULL) {
		printf("memory allocation failed!\n");
		fclose(pFile);
		return NULL;
	}
	memset(pFileBuffer, 0, size);

	result = fread(pFileBuffer, 1, size, pFile);
	if (result != size) {
		printf("Reading file error!\n");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}

	fclose(pFile);


	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	if (pPEHeader->Machine == 0x014c) {
		pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		dwImageSize = pOptionalHeader32->SizeOfImage;
		dwHeaderSize = pOptionalHeader32->SizeOfHeaders;
	}
	else if (pPEHeader->Machine == 0x8664) {
		pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		dwImageSize = pOptionalHeader64->SizeOfImage;
		dwHeaderSize = pOptionalHeader64->SizeOfHeaders;
	}

	if (!(sSections = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER)*pNTHeader->FileHeader.NumberOfSections))) {
		printf("Error allocation memory for Section Headers!\n");
		return 0;
	}
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections;i++)
		memcpy_s(&sSections[i], sizeof(IMAGE_SECTION_HEADER), (const void*)((DWORD)pSectionHeader + i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));


	return pFileBuffer;

}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageFileBuffer)
{

	PIMAGE_DOS_HEADER mpDosHeader = NULL;
	PIMAGE_NT_HEADERS mpNTHeader = NULL;
	PIMAGE_FILE_HEADER mpPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = NULL;
	PIMAGE_SECTION_HEADER mpSectionHeader = NULL;

	DWORD dwmImageSize = 0;
	DWORD dwmHeaderSize = 0;

	mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		dwmImageSize = mpOptionalHeader32->SizeOfImage;
		dwmHeaderSize = mpOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		dwmImageSize = mpOptionalHeader64->SizeOfImage;
		dwmHeaderSize = mpOptionalHeader64->SizeOfHeaders;
	}

	
	DWORD dwSizeCopied = 0;
	char* pImage = NULL;

	if (!(pImage = (char*)malloc(dwmImageSize*sizeof(char)))) {
		printf("Error allocating memory for Image File");
		return 0;
	}

	memset(pImage, 0, dwmImageSize);
		
	//Copy PE Header
	memcpy_s(pImage, dwmHeaderSize, pFileBuffer, dwmHeaderSize);
//	char* pFile = (char*)pFileBuffer;

	dwSizeCopied += dwHeaderSize;
	//Copy Section data
	
	for (int i = 0; i < mpNTHeader->FileHeader.NumberOfSections;i++)
	{
		char* pFile = (char*)((DWORD)pFileBuffer + (mpSectionHeader+i)->PointerToRawData);
//		DWORD tSize = (mpSectionHeader + i)->SizeOfRawData > (mpSectionHeader + i)->Misc.VirtualSize ? (mpSectionHeader + i)->SizeOfRawData : (mpSectionHeader + i)->Misc.VirtualSize;
		memcpy_s((LPVOID)((DWORD)pImage + (mpSectionHeader + i)->VirtualAddress), (mpSectionHeader + i)->SizeOfRawData, (LPVOID)pFile, (mpSectionHeader + i)->SizeOfRawData);
		dwSizeCopied += (mpSectionHeader + i)->SizeOfRawData;
	}

	*pImageFileBuffer = (LPVOID)pImage;
//	free(pImage);
	return dwSizeCopied;
}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
{
	DWORD dwFileSize = 0;
	LPVOID pFile = NULL;
	DWORD dwSizeCopied = 0;
	PIMAGE_DOS_HEADER mpDosHeader = NULL;
	PIMAGE_NT_HEADERS mpNTHeader = NULL;
	PIMAGE_SECTION_HEADER mpSectionHeader = NULL;
	mpDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + mpDosHeader->e_lfanew);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pImageBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);

	DWORD dwSizeNeed = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData > (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize ? \
		(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData:(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize;
	dwFileSize = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->PointerToRawData + dwSizeNeed;

	if (!(pFile = malloc(dwFileSize * sizeof(char)))) {
		printf("Allocation memory for new file buffer error!\n");
		return 0;
	}
	memset(pFile, 0, dwFileSize*sizeof(char));

	memcpy_s(pFile, mpNTHeader->OptionalHeader.SizeOfHeaders, pImageBuffer, mpNTHeader->OptionalHeader.SizeOfHeaders);
	dwSizeCopied += mpNTHeader->OptionalHeader.SizeOfHeaders;

	for (int i = 0;i < mpNTHeader->FileHeader.NumberOfSections;i++) {
		char* pImage = (char*)((DWORD)pImageBuffer + (mpSectionHeader + i)->VirtualAddress);
		memcpy_s(LPVOID((DWORD)pFile + (mpSectionHeader + i)->PointerToRawData), (mpSectionHeader + i)->SizeOfRawData, \
			(LPVOID)pImage, (mpSectionHeader + i)->SizeOfRawData);
		dwSizeCopied += (mpSectionHeader + i)->SizeOfRawData;
	}
	*pNewBuffer = pFile;
	return dwSizeCopied;
}

DWORD CopyImageBufferToNewBuffer2(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
{
	DWORD dwFileSize = 0;
	char* pFile = NULL;
	DWORD dwSizeCopied = 0;
	PIMAGE_DOS_HEADER mpDosHeader = NULL;
	PIMAGE_NT_HEADERS mpNTHeader = NULL;
	PIMAGE_FILE_HEADER mpPEHeader = NULL;
	PIMAGE_SECTION_HEADER mpSectionHeader = NULL;
	int dwmImageSize = 0;
	int dwmHeaderSize = 0;
	mpDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + mpDosHeader->e_lfanew);
	mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageBuffer + mpDosHeader->e_lfanew + 4);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pImageBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);

//	dwFileSize = sSections[pNTHeader->FileHeader.NumberOfSections-1].PointerToRawData+ sSections[pNTHeader->FileHeader.NumberOfSections - 1].SizeOfRawData;
	DWORD dwSizeNeed = ((mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData > (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize)\
		? (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData : (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize;
	dwFileSize = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->PointerToRawData + dwSizeNeed;

	if (!(pFile = (char*)malloc(dwFileSize*sizeof(char))))
	{
		printf("Allocation memory for new file buffer error!\n");
		return 0;
	}
	memset(pFile, 0, (dwFileSize*sizeof(char)));
	
	memcpy_s(pFile, mpNTHeader->OptionalHeader.SizeOfHeaders, pImageBuffer, mpNTHeader->OptionalHeader.SizeOfHeaders);
	dwSizeCopied += mpNTHeader->OptionalHeader.SizeOfHeaders;

	for (int i = 0; i < mpNTHeader->FileHeader.NumberOfSections;i++)
	{
		char* pImage = (char*)((DWORD)pImageBuffer + (mpSectionHeader+i)->VirtualAddress);
		memcpy_s((LPVOID)((DWORD)pFile + (mpSectionHeader + i)->PointerToRawData), (mpSectionHeader + i)->SizeOfRawData, (LPVOID)pImage, (mpSectionHeader + i)->SizeOfRawData);
		dwSizeCopied += (mpSectionHeader + i)->SizeOfRawData;
	}

	*pNewBuffer = (LPVOID)pFile;

	return dwSizeCopied;
}

BOOL MemoryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	FILE* pFile = NULL;
	if (!(pFile = fopen(lpszFile, "wb")))
	{
		printf("Failed to create file for saving!\n");
		return FALSE;
	}

	if (fwrite(pMemBuffer, sizeof(char), size, pFile) == 0) {
		printf("No File saved!\n");
		return FALSE;
	}

	fclose(pFile);
	return TRUE;
}

DWORD RvaToRaw(IN PIMAGE_SECTION_HEADER pSectionHeader, IN PIMAGE_NT_HEADERS pNTHeader, IN DWORD dwRva)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER mpSectionHeader = pSectionHeader;
	if (dwRva == 0 || dwRva <= pNTHeader->OptionalHeader.SizeOfHeaders)
		return dwRva;
	for (i = 0;i < pNTHeader->FileHeader.NumberOfSections;i++) {
		if (dwRva >= mpSectionHeader->VirtualAddress&&dwRva < mpSectionHeader->VirtualAddress + mpSectionHeader->Misc.VirtualSize)
			break;
		mpSectionHeader++;
	}
	return (dwRva - mpSectionHeader->VirtualAddress + mpSectionHeader->PointerToRawData);
}