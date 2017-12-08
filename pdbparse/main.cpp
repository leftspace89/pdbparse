#include <iostream>
#include <iomanip>
#include "pdbparse.h"

//example: parse the win32 ntdll.dll for ApiSetResolveToHost and LdrpHandleTlsData which are not exported but present in the pdb, then output their addresses
int main(int argc, char **argv)
{
	//build a mockup of ntdll so we can parse it
	module_t ntdll;
	{
		//read raw bytes
		ntdll.path = "C:\\Windows\\System32\\ntdll.dll";

		const auto file = CreateFile(ntdll.path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (!file || file == INVALID_HANDLE_VALUE)
			return -1;

		//get file size
		const auto file_size = GetFileSize(file, nullptr);
		if (!file_size)
			return -2;

		//allocate dll bytes and read it
		ntdll.module_on_disk = new uint8_t[file_size];
		ReadFile(file, (LPVOID)ntdll.module_on_disk, file_size, nullptr, nullptr);

		//set image headers
		ntdll.dos_header = (IMAGE_DOS_HEADER*)ntdll.module_on_disk;
		ntdll.ImageHeaders.image_headers64 = (IMAGE_NT_HEADERS64*)(ntdll.module_on_disk + ntdll.dos_header->e_lfanew);

		CloseHandle(file);

		//map sections
		IMAGE_SECTION_HEADER *sections_array = nullptr;
		int section_count = 0;

		ntdll.module_in_memory = new uint8_t[ntdll.ImageHeaders.image_headers64->OptionalHeader.SizeOfImage];
		sections_array = (IMAGE_SECTION_HEADER*)(ntdll.ImageHeaders.image_headers64 + 1);
		section_count = ntdll.ImageHeaders.image_headers64->FileHeader.NumberOfSections;

		for (int i = 0; i < section_count; i++)
		{
			if (sections_array[i].Characteristics & 0x800)
				continue;

			memcpy_s(ntdll.module_in_memory + sections_array[i].VirtualAddress, sections_array[i].SizeOfRawData, ntdll.module_on_disk + sections_array[i].PointerToRawData, sections_array[i].SizeOfRawData);
		}

		//set image base
		ntdll.module_base = (uintptr_t)GetModuleHandle("ntdll.dll");
	}

	const auto api_set_resolve_to_host = pdb_parse::get_address_from_symbol("ApiSetResolveToHost", ntdll, false);

	if (api_set_resolve_to_host)
		std::cout << "ApiSetResolveToHost found: 0x" << std::setfill('0') << std::setw(16) << std::hex << api_set_resolve_to_host << std::endl;
	else
		std::cout << "ApiSetResolveToHost not found!" << std::endl;

	const auto handle_tls_data = pdb_parse::get_address_from_symbol("LdrpHandleTlsData", ntdll, false);

	if (handle_tls_data)
		std::cout << "LdrpHandleTlsData found: 0x" << std::setw(16) << std::hex << handle_tls_data << std::endl;
	else
		std::cout << "LdrpHandleTlsData not found!" << std::endl;

	std::cin.get();

	return 0;
}