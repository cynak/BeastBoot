/* beastmount: attach an ISO file read-only in Windows PE (BeastBoot, build/winpe/).
 *
 *   beastmount.exe D:\path\to.iso        attach read-only; exit 0: attached (it stays
 *                                        attached after exit; Windows shows a new drive)
 *   beastmount.exe --running E: SECONDS  wait up to SECONDS (0: look once) for Windows
 *                                        Setup (setup.exe, setuphost.exe, setupprep.exe)
 *                                        running from drive E:; print its path, exit 0;
 *                                        exit 1 if there is none
 *   beastmount.exe --sleep SECONDS       wait (Windows PE has no timeout.exe, and ping
 *                                        127.0.0.1 needs the network stack)
 *   beastmount.exe --version
 *
 * Windows Setup's Windows PE (boot.wim index 2) has the VirtDisk API (virtdisk.dll,
 * vhdmp.sys) but nothing built in that attaches an ISO: diskpart's "select vdisk"
 * accepts only VHD/VHDX ("The parameter is incorrect" for an ISO), and there is no
 * PowerShell, wmic or storage WMI provider (MSFT_DiskImage). beastboot.cmd runs this
 * helper instead. --running is how the script proves Setup started from the attached
 * ISO: tasklist shows process names only, and the RAM disk has an X:\setup.exe too.
 *
 * Built by build/winpe/beastmountsrc.py with the pinned MinGW-w64 cross compiler
 * (build/winpe/mingw-w64.lock.json), reproducibly; shipped as
 * esp/beast-booter/winpe/beastmount.exe and injected by the menu in setup mode.
 *
 * virtdisk.dll is loaded at run time, so the program needs no import library and
 * fails with a clear message where the API is missing. Imports: KERNEL32, msvcrt.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>

#define BEASTMOUNT_VERSION "1.0"

/* The parts of virtdisk.h we use (Windows SDK, VirtDisk API version 1). */
typedef struct {
	ULONG DeviceId;
	GUID VendorId;
} BB_VIRTUAL_STORAGE_TYPE;

typedef struct {
	int Version;
	struct {
		ULONG Reserved;
	} Version1;
} BB_ATTACH_PARAMETERS;

typedef DWORD (WINAPI *open_vd_t)(BB_VIRTUAL_STORAGE_TYPE *, PCWSTR, int, int, void *, HANDLE *);
typedef DWORD (WINAPI *attach_vd_t)(HANDLE, PSECURITY_DESCRIPTOR, int, ULONG, BB_ATTACH_PARAMETERS *,
				    LPOVERLAPPED);

#define BB_STORAGE_TYPE_DEVICE_ISO 1
#define BB_ACCESS_READ 0x000d0000		/* VIRTUAL_DISK_ACCESS_READ */
#define BB_ATTACH_READ_ONLY 0x00000001		/* ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY */
#define BB_ATTACH_PERMANENT 0x00000004		/* ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME */

/* VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT */
static const GUID vendor_microsoft =
	{ 0xec984aec, 0xa0f9, 0x47e9, { 0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b } };

static int attach(const wchar_t *iso)
{
	BB_VIRTUAL_STORAGE_TYPE type;
	BB_ATTACH_PARAMETERS params;
	open_vd_t open_vd;
	attach_vd_t attach_vd;
	HMODULE lib;
	HANDLE disk = NULL;
	DWORD err;

	lib = LoadLibraryW(L"virtdisk.dll");
	if (!lib) {
		fwprintf(stderr, L"beastmount: virtdisk.dll is missing here (error %lu)\n", GetLastError());
		return 3;
	}
	open_vd = (open_vd_t)(void *)GetProcAddress(lib, "OpenVirtualDisk");
	attach_vd = (attach_vd_t)(void *)GetProcAddress(lib, "AttachVirtualDisk");
	if (!open_vd || !attach_vd) {
		fwprintf(stderr, L"beastmount: virtdisk.dll has no OpenVirtualDisk/AttachVirtualDisk\n");
		return 3;
	}

	type.DeviceId = BB_STORAGE_TYPE_DEVICE_ISO;
	type.VendorId = vendor_microsoft;
	err = open_vd(&type, iso, BB_ACCESS_READ, 0, NULL, &disk);
	if (err != ERROR_SUCCESS) {
		fwprintf(stderr, L"beastmount: cannot open %ls as an ISO image (error %lu)\n", iso, err);
		return 1;
	}
	ZeroMemory(&params, sizeof(params));
	params.Version = 1;
	err = attach_vd(disk, NULL, BB_ATTACH_READ_ONLY | BB_ATTACH_PERMANENT, 0, &params, NULL);
	CloseHandle(disk);
	if (err != ERROR_SUCCESS) {
		fwprintf(stderr, L"beastmount: cannot attach %ls read-only (error %lu)\n", iso, err);
		return 1;
	}
	fwprintf(stderr, L"beastmount: attached %ls read-only\n", iso);
	return 0;
}

static int is_setup_name(const wchar_t *name)
{
	return !_wcsicmp(name, L"setup.exe") || !_wcsicmp(name, L"setuphost.exe") ||
	       !_wcsicmp(name, L"setupprep.exe");
}

/* Full path of a Setup process whose image is on DRIVE ("E:"), into PATH; 0 if none. */
static int find_setup(const wchar_t *drive, wchar_t *path, DWORD size)
{
	PROCESSENTRY32W pe;
	HANDLE snap, proc;
	DWORD len;
	int found = 0;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 0;
	pe.dwSize = sizeof(pe);
	for (BOOL ok = Process32FirstW(snap, &pe); ok && !found; ok = Process32NextW(snap, &pe)) {
		if (!is_setup_name(pe.szExeFile))
			continue;
		proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
		if (!proc)
			continue;
		len = size;
		if (QueryFullProcessImageNameW(proc, 0, path, &len) && len > 3 &&
		    towupper(path[0]) == towupper(drive[0]) && path[1] == L':' && path[2] == L'\\')
			found = 1;
		CloseHandle(proc);
	}
	CloseHandle(snap);
	return found;
}

static int running(const wchar_t *drive, const wchar_t *secs)
{
	wchar_t path[MAX_PATH + 1];
	long wait = wcstol(secs, NULL, 10);

	if (!iswalpha(drive[0]) || (drive[1] != L'\0' && (drive[1] != L':' || drive[2] != L'\0')) ||
	    wait < 0 || wait > 3600) {
		fwprintf(stderr, L"usage: beastmount --running LETTER: SECONDS\n");
		return 2;
	}
	for (long i = 0;; i++) {
		if (find_setup(drive, path, MAX_PATH)) {
			wprintf(L"%ls\n", path);
			return 0;
		}
		if (i >= wait)
			return 1;
		Sleep(1000);
	}
}

int wmain(int argc, wchar_t **argv)
{
	if (argc == 2 && !wcscmp(argv[1], L"--version")) {
		wprintf(L"beastmount " BEASTMOUNT_VERSION "\n");
		return 0;
	}
	if (argc == 4 && !wcscmp(argv[1], L"--running"))
		return running(argv[2], argv[3]);
	if (argc == 3 && !wcscmp(argv[1], L"--sleep")) {
		long secs = wcstol(argv[2], NULL, 10);
		if (secs < 0 || secs > 3600) {
			fwprintf(stderr, L"usage: beastmount --sleep SECONDS (0-3600)\n");
			return 2;
		}
		Sleep((DWORD)secs * 1000);
		return 0;
	}
	if (argc != 2 || argv[1][0] == L'-') {
		fwprintf(stderr, L"usage: beastmount FILE.iso | --running LETTER: SECONDS | --sleep SECONDS | --version\n");
		return 2;
	}
	return attach(argv[1]);
}
