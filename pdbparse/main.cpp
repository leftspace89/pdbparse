//example: parse the wow64 and win32 (if x64) ntdlls for ApiSetResolveToHost and LdrpHandleTlsData which are not exported but present in the pdb, then output their addresses

#include <iostream>
#include <iomanip>
#include "pdbparse.hpp"

//undefined on x86, define it here so we can use constexpr if statements instead of ugly macros
#ifndef _M_X64
#define _M_X64 0
#endif

//helper function to parse a module
static module_t get_module_info(std::string_view path, bool is_wow64)
{
	//read raw bytes
	const auto file = CreateFile(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (!file || file == INVALID_HANDLE_VALUE)
		return module_t();

	//get file size
	const auto file_size = GetFileSize(file, nullptr);

	if (!file_size)
		return module_t();

	//allocate dll bytes and read it
	auto module_on_disk = std::make_unique<uint8_t[]>(file_size);
	ReadFile(file, (LPVOID)module_on_disk.get(), file_size, nullptr, nullptr);

	//set image headers
	auto dos_header = (IMAGE_DOS_HEADER*)module_on_disk.get();
	auto image_headers = (void*)(module_on_disk.get() + dos_header->e_lfanew);

	auto image_headers32 = (IMAGE_NT_HEADERS32*)image_headers;
	auto image_headers64 = (IMAGE_NT_HEADERS64*)image_headers;

	CloseHandle(file);

	//map sections
	IMAGE_SECTION_HEADER *sections_array = nullptr;
	int section_count = 0;

	std::unique_ptr<uint8_t[]> module_in_memory = nullptr;
	if (is_wow64)
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers32->OptionalHeader.SizeOfImage);
		sections_array = (IMAGE_SECTION_HEADER*)(image_headers32 + 1);
		section_count = image_headers32->FileHeader.NumberOfSections;
	}
	else
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers64->OptionalHeader.SizeOfImage);
		sections_array = (IMAGE_SECTION_HEADER*)(image_headers64 + 1);
		section_count = image_headers64->FileHeader.NumberOfSections;
	}

	for (int i = 0; i < section_count; i++)
	{
		if (sections_array[i].Characteristics & 0x800)
			continue;

		memcpy_s(module_in_memory.get() + sections_array[i].VirtualAddress, sections_array[i].SizeOfRawData, module_on_disk.get() + sections_array[i].PointerToRawData, sections_array[i].SizeOfRawData);
	}

	return module_t(0, module_on_disk, module_in_memory, dos_header, path, image_headers);
}

static void output_function_address(std::string_view function_name, const module_t &module_info, bool is_wow64)
{
	const auto function_address = pdb_parse::get_address_from_symbol(function_name, module_info, is_wow64);

	if (function_address)
		std::cout << function_name << " found: 0x" << std::setfill('0') << std::setw(16) << std::hex << function_address << std::endl;
	else
		std::cout << function_name << " not found!" << std::endl;
};

int main(int argc, char **argv)
{
	std::cout << "x86 ntdll:" << std::endl;

	//this path will only work if your OS is x64-based
	//if it's x86-based, use System32
	const auto ntdll32 = get_module_info("C:\\Windows\\SysWOW64\\ntdll.dll", true);

	output_function_address("ApiSetResolveToHost", ntdll32, true);
	output_function_address("LdrpHandleTlsData", ntdll32, true);

	if constexpr(_M_X64)
	{
		std::cout << "\nx64 ntdll:" << std::endl;

		const auto ntdll64 = get_module_info("C:\\Windows\\System32\\ntdll.dll", false);

		output_function_address("ApiSetResolveToHost", ntdll64, false);
		output_function_address("LdrpHandleTlsData", ntdll64, false);
	}

	std::cin.get();

	return 0;
}