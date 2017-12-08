#pragma once
#include <Windows.h>
#include <winnt.h>
#include <cstdint>
#include <string>

struct module_t
{
	//the modules's address in the process
	uintptr_t module_base = 0;

	//a pointer to the bytes of the DLL on disk
	uint8_t *module_on_disk = nullptr;

	//the bytes of the module in memory
	uint8_t *module_in_memory = nullptr;

	//the module's DOS header
	IMAGE_DOS_HEADER *dos_header = nullptr;

	//the module's path
	std::string path;

	//the module's PE header
	union
	{
		IMAGE_NT_HEADERS32 *image_headers32;
		IMAGE_NT_HEADERS64 *image_headers64;
	} ImageHeaders;

	~module_t()
	{
		delete[] module_in_memory;
		delete[] module_on_disk;
	}
};

//used with maps which take in std::strings so it compares in lowercase
struct map_compatator
{
	bool operator() (const std::string &left, const std::string &right) const { return !_stricmp(left.c_str(), right.c_str()); }
};