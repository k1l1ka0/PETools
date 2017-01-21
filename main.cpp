#include "Global.h"

int main(int argc, char** argv)
{
	LPSTR lpFilename = argv[1];
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewBuffer = NULL;
	DWORD test = 0;

	if (argc != 3) {
		printf("Usage: ReadPE \"Input filename\" \"out\"\n");
		return 1;
	}

/*	
	if (!PrintHeaders(argv[1])) {
		printf("Error in Printing headers!\n");
		return 0;
	}
*/
	if (!(pFileBuffer = ReadPEFile(lpFilename)))
	{
		printf("Read file %s error!\n", lpFilename);
		return 0;
	}

/*	test = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (test == 0) {
		printf("error copy file buffer to image buffer!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return 0;
	}

	
	test = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (test == 0) {
		printf("error copy image buffer to new buffer!\n");
		free(pFileBuffer);
		free(pImageBuffer);
		free(pNewBuffer);
		return 0;
	}

	if (!MemoryToFile(pNewBuffer, test, argv[2]))
	{
		printf("Save file error!\n");
		free(pFileBuffer);
		free(pNewBuffer);
		return 0;
	}
*/
/*	
	if (!InjectIntoSection(pFileBuffer, 0, argv[2])) {
		printf("error saving code to %s", argv[2]);
		free(pFileBuffer);
		free(pImageBuffer);
		free(pNewBuffer);
		return 0;
	}
*/
	//ExpandLastSection(pFileBuffer, 0x1000, argv[2]);

	//PrintExportTable(pFileBuffer);
	//printf("%X\n",SearchEATByName(pFileBuffer, "_Assemble"));
	//printf("%X\n", SearchEATByOrdinal(pFileBuffer, 164));
	//PrintRelocationTable(pFileBuffer);
	//MoveEAT(pFileBuffer, argv[2]);
	PrintIAT(pFileBuffer);

	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	return 1;
}