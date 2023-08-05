#include "kraken.h"

PBYTE FindGadget(PVOID base, DWORD size, PBYTE pattern, DWORD patternSize)
{
	for (DWORD i = 0; i < size - patternSize; i++)
	{
		if (memcmp((PBYTE)base + i, pattern, patternSize) == 0)
		{
			return (PBYTE)base + i;
		}
	}
	return 0x0;
}

DWORD HashStringDjb2W(LPCWSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

DWORD HashStringDjb2A(LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

PVOID SearchGadgetOnKernelBaseModule(PBYTE pbPattern, DWORD dwPatternSize)
{
	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	PVOID pLdrDataEntryFirstEntry = (PVOID)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink);

	LIST_ENTRY* pListParser = (DWORD64)pLdrDataEntryFirstEntry - 0x10;
	while (pListParser->Flink != pLdrDataEntryFirstEntry)
	{
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = pListParser;
		if (HashStringDjb2W(pLdrDataEntry->BaseDllName.Buffer) == 0x3ec3feb)
		{
			PVOID pGagetRet = FindGadget(pLdrDataEntry->DllBase, (DWORD)pLdrDataEntry->SizeOfImage, pbPattern, dwPatternSize);
			return pGagetRet;
		}
		pListParser = pListParser->Flink;
	}
}

PVOID GetNtdllAddr() {
	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	return ((PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10))->DllBase;
}


PVOID Spoofer(PVOID pFunction, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8)
{
	BYTE bPattern[] = { 0xFF, 0x23 };

	PVOID pGadgetAddr = NULL;
	pGadgetAddr = SearchGadgetOnKernelBaseModule(bPattern, 2);
	PRM param = { pGadgetAddr, pFunction };

	PVOID pRet = SpoofStub(pArg1, pArg2, pArg3, pArg4, &param, pArg5, pArg6, pArg7, pArg8);
	return pRet;
}

VOID GenerateKey(BYTE* key, DWORD keySize)
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	SPOOF(BCryptOpenAlgorithmProvider, &hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL);
	SPOOF(BCryptGenRandom,hAlgorithm, key, keySize);
	SPOOF(BCryptCloseAlgorithmProvider,hAlgorithm, 0);
}


BOOL TakeSectionInfo(PSECTION_INFO SecInfo) 
{

	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pCurrentPeb->ImageBaseAddress;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pCurrentPeb->ImageBaseAddress + pImageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

	for (WORD i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++) {
		if (HashStringDjb2A(pSectionHeader[i].Name) == 0xb80c0d8)
		{
			SecInfo->pAddr = (((DWORD_PTR)pCurrentPeb->ImageBaseAddress) + pSectionHeader[i].VirtualAddress);
			(DWORD_PTR)SecInfo->pAddr += SECTION_HEADER_SIZE;
			SecInfo->dwSize = (pSectionHeader[i].SizeOfRawData - SECTION_HEADER_SIZE);

			return TRUE;
		}

	}
	return FALSE;
}

