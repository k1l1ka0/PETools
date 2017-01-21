#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHELLCODELENGTH	0x12
#define MESSAGEBOXADDR 0X75358830

/*--------File Header & operation global vars-----------------*/
extern PIMAGE_DOS_HEADER pDosHeader;
extern PIMAGE_NT_HEADERS pNTHeader;
extern PIMAGE_FILE_HEADER pPEHeader;
extern PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32;
extern PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64;
extern PIMAGE_SECTION_HEADER pSectionHeader;
extern PIMAGE_SECTION_HEADER sSections;
extern DWORD dwImageSize;
extern DWORD dwHeaderSize;

extern BYTE shellcode[];

LPVOID ReadPEFile(LPSTR lpszFilename);
//Read PE File into memory and return the memory block, if error returns NULL;

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageFileBuffer);
// Copy PE file into New Image Buffer, if error return 0, else return size of copied size

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);
//Copy Image File into PE file, if error return 0, else return size copied

BOOL MemoryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);
//Save memory into file, return TRUE if success

DWORD RvaToRaw(IN PIMAGE_SECTION_HEADER pSectionHeader, IN PIMAGE_NT_HEADERS pNTHeader, IN DWORD dwRva);
//Calculate RVA to RAW

int PrintHeaders(LPSTR lpFilename);
//Print Out PE headers 

BOOL InjectIntoSection(IN LPVOID pFileBuffer, size_t n, OUT LPSTR lpszFileName);
//Inject Shellcode into Section N
//If n=0, or section not enough to inject the code, add a new section and inject into the session
//If not enough room, try to shorten the dos stub data, if still cannot, then add code into the last section
//output into file, return TURE if success

VOID ExpandLastSection(IN LPVOID pFileBuffer, IN size_t ex, OUT LPSTR lpszFileName);
//Expand the last Section of PE file
//Record original virtual size, CodeBegin = virtualsize+pointertoraw; pSectionHeader->VirtualSize+=codesize; pSH->sizeofraw=align(pSH->misc.virtualsize,file_align)
//sizeofimage=align(pSH->misc.virtualsize,section_align)

DWORD InsertNewSection(IN LPVOID pFileBuffer, IN size_t n, OUT LPVOID* pNewBuffer);
//Insert a new section at last 
//return FOA if success, 0 if error

//----------------Directory Functions-----------------------------

VOID PrintExportTable(LPVOID pFileBuffer);
//Print the export table

DWORD SearchEATByName(IN LPVOID pFileBuffer, IN LPSTR FuncName);
//Return Function RVA with Function Name
//If No EAT, or Not found the name, return 0

DWORD SearchEATByOrdinal(IN LPVOID pFileBuffer, IN WORD Ordinal);
//Return Function RVA with Ordinal
//If No EAT, or Not found the name, return 0

VOID PrintRelocationTable(LPVOID pFileBuffer);
//Print the relocation table

VOID MoveEAT(IN LPVOID pFileBuffer, OUT LPSTR lpszFileName);
//Add a New Section to file and copy EAT/Names to New Section, and repair the directory

VOID PrintIAT(IN LPVOID pFileBuffer);
//Print the Import Address Table