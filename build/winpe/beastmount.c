/* beastmount: attach an ISO file read-only in Windows PE (BeastBoot, build/winpe/).
 *
 *   beastmount.exe D:\path\to.iso      exit 0: attached (it stays attached after exit)
 *
 * Windows Setup's Windows PE (boot.wim index 2) has the VirtDisk API (virtdisk.dll,
 * vhdmp.sys) but nothing built in that attaches an ISO: diskpart's "select vdisk"
 * accepts only VHD/VHDX ("The parameter is incorrect" for an ISO), and there is no
 * PowerShell, wmic or storage WMI provider (MSFT_DiskImage). beastboot.cmd runs this
 * helper instead; Windows then shows the ISO as a new CD-ROM drive.
 *
 * NOT BUILT OR SHIPPED YET: proven in the manual chain check (tests/e2e/REAL_ISOS.md,
 * Windows section) with x86_64-w64-mingw32-gcc 13 (Ubuntu 26.04 gcc-mingw-w64-x86-64):
 *   x86_64-w64-mingw32-gcc -municode -O2 -s -Wall -Wl,--no-insert-timestamp \
 *       -o beastmount.exe beastmount.c
 * Shipping it needs a pinned, reproducible MinGW-w64 build step (a new toolchain).
 *
 * virtdisk.dll is loaded at run time, so the program needs no import library and
 * fails with a clear message where the API is missing.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

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

int wmain(int argc, wchar_t **argv)
{
	BB_VIRTUAL_STORAGE_TYPE type;
	BB_ATTACH_PARAMETERS params;
	open_vd_t open_vd;
	attach_vd_t attach_vd;
	HMODULE lib;
	HANDLE disk = NULL;
	DWORD err;

	if (argc != 2) {
		fwprintf(stderr, L"usage: beastmount FILE.iso\n");
		return 2;
	}
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
	err = open_vd(&type, argv[1], BB_ACCESS_READ, 0, NULL, &disk);
	if (err != ERROR_SUCCESS) {
		fwprintf(stderr, L"beastmount: cannot open %ls as an ISO image (error %lu)\n", argv[1], err);
		return 1;
	}
	ZeroMemory(&params, sizeof(params));
	params.Version = 1;
	err = attach_vd(disk, NULL, BB_ATTACH_READ_ONLY | BB_ATTACH_PERMANENT, 0, &params, NULL);
	CloseHandle(disk);
	if (err != ERROR_SUCCESS) {
		fwprintf(stderr, L"beastmount: cannot attach %ls read-only (error %lu)\n", argv[1], err);
		return 1;
	}
	wprintf(L"beastmount: attached %ls read-only\n", argv[1]);
	return 0;
}
