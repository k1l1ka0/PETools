#include "Global.h"

BOOL IsNullSection(IMAGE_SECTION_HEADER SectionHeader)
{
	if ((SectionHeader.Misc.VirtualSize + SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData + SectionHeader.VirtualAddress + SectionHeader.Characteristics) == 0)
			return TRUE;
	return FALSE;
}

BOOL InjectIntoSection(IN LPVOID pFileBuffer, size_t n, OUT LPSTR lpszFileName)
{
	LPVOID pNewBuffer = NULL;
	PIMAGE_SECTION_HEADER mpSectionHeader = NULL;
	LPVOID mpImageBuffer = NULL;
	LPVOID mpNewImageBuffer = NULL;
	const IMAGE_SECTION_HEADER NullSectionHeader = { 00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00 };

	CopyFileBufferToImageBuffer(pFileBuffer, &mpImageBuffer);
	if (!mpImageBuffer){
		printf("Error copying file into image!\n ");
		return FALSE;
	}

	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)mpImageBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpImageBuffer + mpDosHeader->e_lfanew);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)mpImageBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	DWORD dwmImageSize = mpNTHeader->OptionalHeader.SizeOfImage;

	//disable ASLR
	mpNTHeader->OptionalHeader.DllCharacteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	if (n > mpNTHeader->FileHeader.NumberOfSections) {
		printf("Unknown section to inject!\n");
		return FALSE;
	}
	
	//Add new section
	if (n == 0)
	{
		//calculate how much sectionalignments needed to add shellcode
		DWORD wSizeNeed = (DWORD)(((SHELLCODELENGTH-1) / mpNTHeader->OptionalHeader.SectionAlignment) + 1)*mpNTHeader->OptionalHeader.SectionAlignment;
		
//		DWORD dwmImageSize = mpNTHeader->OptionalHeader.SizeOfImage;

		if (!(mpNewImageBuffer = (char*)malloc(dwmImageSize+wSizeNeed))) {
			printf("Error allocating memory for new file!\n");
			return FALSE;
		}
		memset(mpNewImageBuffer, 0, dwmImageSize + wSizeNeed);
		memcpy_s(mpNewImageBuffer, dwmImageSize, mpImageBuffer, dwmImageSize);

		PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)mpNewImageBuffer;
		PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpNewImageBuffer + mpDosHeader->e_lfanew);
		mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)mpNewImageBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
		
		//disable ASLR
		mpNTHeader->OptionalHeader.DllCharacteristics |= IMAGE_FILE_RELOCS_STRIPPED;


		//try to see if section table is big enough
		if (((mpSectionHeader->PointerToRawData - (DWORD)mpSectionHeader + (DWORD)mpNewImageBuffer) < (mpNTHeader->FileHeader.NumberOfSections + 1) * 0x28) || \
			!IsNullSection(*(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections))) {
			DWORD stubSize = (DWORD)mpNTHeader - (DWORD)pDosHeader - sizeof(IMAGE_DOS_HEADER);
			if (((mpNTHeader->FileHeader.NumberOfSections + 1) * 0x28 - (mpSectionHeader->PointerToRawData - (DWORD)mpSectionHeader + (DWORD)mpNewImageBuffer)) > stubSize)
			{
				printf("No enough place for new section!\n");
				return FALSE;
			}

			//Shrink Dos stub
			mpDosHeader->e_lfanew = (DWORD)mpDosHeader + sizeof(IMAGE_DOS_HEADER);
			DWORD dwSizeToMove = (DWORD)(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections) - (DWORD)mpNTHeader;
			char* tFile = (char*)mpDosHeader->e_lfanew;
			for (DWORD i = 0;i < dwSizeToMove;i++, tFile++)
				tFile = (char*)(tFile + stubSize);

			//recalc the Headers
			PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpNewImageBuffer + mpDosHeader->e_lfanew);
			mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)mpNewImageBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
		}
//		if (((mpSectionHeader->PointerToRawData - (DWORD)mpSectionHeader+(DWORD)mpNewImageBuffer) >= (mpNTHeader->FileHeader.NumberOfSections + 1) * 0x28) && \
			IsNullSection(*(mpSectionHeader+mpNTHeader->FileHeader.NumberOfSections)))
		{
			
			//Insert new section table
			PIMAGE_SECTION_HEADER mpFirstSection = (PIMAGE_SECTION_HEADER)mpSectionHeader;
			for (int i = 0;i < mpNTHeader->FileHeader.NumberOfSections;i++, mpSectionHeader++);
			mpNTHeader->FileHeader.NumberOfSections++;
			mpNTHeader->OptionalHeader.SizeOfImage += wSizeNeed;
			//copy the first section header into the last;
			memcpy_s(mpSectionHeader,sizeof(IMAGE_SECTION_HEADER),mpFirstSection,sizeof(IMAGE_SECTION_HEADER));
			mpSectionHeader++;
			*mpSectionHeader = NullSectionHeader;
			mpSectionHeader--;
			memcpy_s(mpSectionHeader,0x8,"NewSec\0\0",0x8);
			mpSectionHeader->Misc.VirtualSize = wSizeNeed;
			DWORD tmpSize = (mpSectionHeader - 1)->SizeOfRawData > (mpSectionHeader - 1)->Misc.VirtualSize ? (mpSectionHeader - 1)->SizeOfRawData : (mpSectionHeader - 1)->Misc.VirtualSize;
			mpSectionHeader->VirtualAddress = (mpSectionHeader - 1)->VirtualAddress + ((int)((tmpSize-1)/pNTHeader->OptionalHeader.SectionAlignment)+1)*(pNTHeader->OptionalHeader.SectionAlignment);
			mpSectionHeader->SizeOfRawData = wSizeNeed;
			mpSectionHeader->PointerToRawData = (mpSectionHeader-1)->PointerToRawData+(mpSectionHeader-1)->SizeOfRawData;
			mpSectionHeader->Characteristics |= (0x60000020);

			PBYTE CodeBegin = (PBYTE)((DWORD)mpNewImageBuffer + mpSectionHeader->VirtualAddress);
			memcpy_s(CodeBegin, SHELLCODELENGTH, shellcode, SHELLCODELENGTH);

			//Revise E8
			DWORD CallAddr = (MESSAGEBOXADDR - (mpNTHeader->OptionalHeader.ImageBase + (DWORD)(CodeBegin + 0xD) - (DWORD)mpNewImageBuffer));
			*(PDWORD)(CodeBegin + 9) = CallAddr;
			//Revise E9
			DWORD JmpAddr = (mpNTHeader->OptionalHeader.AddressOfEntryPoint - ((DWORD)(CodeBegin + 0x12) - (DWORD)mpNewImageBuffer));
			*(PDWORD)(CodeBegin + 0xE) = JmpAddr;
			//Revise OEP
			mpNTHeader->OptionalHeader.AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)mpNewImageBuffer;

			DWORD size = CopyImageBufferToNewBuffer(mpNewImageBuffer, &pNewBuffer);
			if (size == 0 || !pNewBuffer) {
				printf("error saving to new buffer!\n");
				return FALSE;
			}
			if (!MemoryToFile(pNewBuffer, size, lpszFileName))
			{
				printf("error saving to file %s!\n",lpszFileName);
				return FALSE;
			}
			return TRUE;
		}
		
	}

//Insert into section n-1
	for (size_t t = 0;t < n - 1; t++)
		mpSectionHeader++;

	//check if spare space enough for shellcode
	if ((mpSectionHeader->SizeOfRawData - mpSectionHeader->Misc.VirtualSize) < SHELLCODELENGTH)
	{
		printf("Not enough space for inserting code!\n");
		free(mpImageBuffer);
		return FALSE;
	}
	
	PBYTE CodeBegin = (PBYTE)((DWORD)mpImageBuffer + mpSectionHeader->VirtualAddress + mpSectionHeader->Misc.VirtualSize);
	memcpy_s(CodeBegin, SHELLCODELENGTH, shellcode, SHELLCODELENGTH);

	//Revise E8
	DWORD CallAddr = (MESSAGEBOXADDR - (mpNTHeader->OptionalHeader.ImageBase + (DWORD)(CodeBegin + 0xD) - (DWORD)mpImageBuffer));
	*(PDWORD)(CodeBegin + 9) = CallAddr;
	//Revise E9
	DWORD JmpAddr = (mpNTHeader->OptionalHeader.AddressOfEntryPoint - ((DWORD)(CodeBegin + 0x12) - (DWORD)mpImageBuffer));
	*(PDWORD)(CodeBegin + 0xE) = JmpAddr;
	//Revise OEP
	mpNTHeader->OptionalHeader.AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)mpImageBuffer;
	//Revise section characteristic to be readable, writable and excutable
	
	mpSectionHeader->Characteristics |= 0x60000020;

	DWORD size = CopyImageBufferToNewBuffer(mpImageBuffer, &pNewBuffer);
	if (size == 0 || !pNewBuffer) {
		printf("error wrtie to new buffer!\n");
		return FALSE;
	}
	if (!MemoryToFile(pNewBuffer, size, lpszFileName))
	{
		printf("error saving file!\n");
		return FALSE;
	}
	return TRUE;
}

VOID ExpandLastSection(IN LPVOID pFileBuffer, IN size_t ex, OUT LPSTR lpszFileName)
{
	LPVOID mpImageBuffer = NULL;
	LPVOID mpNewImageBuffer = NULL;
	LPVOID mpNewBuffer = NULL;

	if (CopyFileBufferToImageBuffer(pFileBuffer, &mpImageBuffer) == 0) {
		printf("Errror copy file to image!");
		return;
	}
	
	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)mpImageBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpImageBuffer + mpDosHeader->e_lfanew);
	
	ex = ((ex - 1) / mpNTHeader->OptionalHeader.FileAlignment + 1)*mpNTHeader->OptionalHeader.FileAlignment;

	if (!(mpNewImageBuffer = malloc(mpNTHeader->OptionalHeader.SizeOfImage + ex))) {
		printf("error allocating memory for new image!\n");
		return;
	}
	memset(mpNewImageBuffer, 0, mpNTHeader->OptionalHeader.SizeOfImage + ex);
	memcpy_s(mpNewImageBuffer, mpNTHeader->OptionalHeader.SizeOfImage, mpImageBuffer, mpNTHeader->OptionalHeader.SizeOfImage);

	mpDosHeader = (PIMAGE_DOS_HEADER)mpNewImageBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpNewImageBuffer + mpDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)mpNewImageBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	DWORD size = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize > (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData ? \
		(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize:(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData;
	if(size!=0)
		size = ((int)((size-1) / mpNTHeader->OptionalHeader.SectionAlignment) + 1) * mpNTHeader->OptionalHeader.SectionAlignment+ex;
	(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->Misc.VirtualSize = size;
	(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData = ((size-1)/mpNTHeader->OptionalHeader.FileAlignment)*mpNTHeader->OptionalHeader.FileAlignment;
	mpNTHeader->OptionalHeader.SizeOfImage += ex;

	DWORD sizeCopied = CopyImageBufferToNewBuffer(mpNewImageBuffer, &mpNewBuffer);
	if (sizeCopied == 0) {
		printf("Error copying to new file!\n");
		return;
	}
	if (!MemoryToFile(mpNewBuffer, sizeCopied, lpszFileName)) {
		printf("error saving file to %s!\n", lpszFileName);
		return;
	}
	return;
}

DWORD InsertNewSection(IN LPVOID pFileBuffer, IN size_t n, OUT LPVOID* pNewBuffer) 
{
	LPVOID mpNewBuffer = NULL;
	
	const IMAGE_SECTION_HEADER NullSectionHeader = { 00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00 };

	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);

	n = ((n - 1) / mpNTHeader->OptionalHeader.FileAlignment+1)*mpNTHeader->OptionalHeader.FileAlignment;

	DWORD dwFileSize = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->PointerToRawData + (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData + n;

	if (!(mpNewBuffer = (LPVOID)malloc(dwFileSize))) {
		printf("Error allocating memory for new buffer.\n");
		return 0;
	}

	memset(mpNewBuffer, 0, dwFileSize);
	memcpy_s(mpNewBuffer, (dwFileSize - n), pFileBuffer, (dwFileSize - n));

	mpDosHeader = (PIMAGE_DOS_HEADER)mpNewBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpNewBuffer + mpDosHeader->e_lfanew);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)mpNewBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);

	if (((mpSectionHeader->PointerToRawData - (DWORD)mpSectionHeader + (DWORD)mpNewBuffer) >= (mpNTHeader->FileHeader.NumberOfSections + 1) * 0x28) && \
		IsNullSection(*(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections)))
	{

		//Insert new section table
		PIMAGE_SECTION_HEADER mpFirstSection = (PIMAGE_SECTION_HEADER)mpSectionHeader;
		mpSectionHeader += mpNTHeader->FileHeader.NumberOfSections;
		mpNTHeader->FileHeader.NumberOfSections++;
		mpNTHeader->OptionalHeader.SizeOfImage += n;
		//copy the first section header into the last;
		memcpy_s(mpSectionHeader, sizeof(IMAGE_SECTION_HEADER), mpFirstSection, sizeof(IMAGE_SECTION_HEADER));
		*(mpSectionHeader + 1) = NullSectionHeader;
		memcpy_s(mpSectionHeader, 0x8, "NewSec\0\0", 0x8);
		mpSectionHeader->Misc.VirtualSize = n;
		DWORD tmpSize = (mpSectionHeader - 1)->SizeOfRawData > (mpSectionHeader - 1)->Misc.VirtualSize ? (mpSectionHeader - 1)->SizeOfRawData : (mpSectionHeader - 1)->Misc.VirtualSize;
		mpSectionHeader->VirtualAddress = (mpSectionHeader - 1)->VirtualAddress + ((int)((tmpSize - 1) / pNTHeader->OptionalHeader.SectionAlignment) + 1)*(pNTHeader->OptionalHeader.SectionAlignment);
		mpSectionHeader->SizeOfRawData = n;
		mpSectionHeader->PointerToRawData = (mpSectionHeader - 1)->PointerToRawData + (mpSectionHeader - 1)->SizeOfRawData;
		mpSectionHeader->Characteristics |= (0x60000020);

		*pNewBuffer = mpNewBuffer;
		return (DWORD)mpSectionHeader->PointerToRawData;
	}
	return 0;
}