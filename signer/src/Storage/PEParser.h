#pragma once
#include <windows.h>
#include <vector>
#include <tuple>
namespace Signer
{
	namespace PEParser
	{
		std::pair<void*, unsigned long> LoadFile(const char* path);
		bool ParsePE(const char* path, std::vector<BYTE>* data, PIMAGE_NT_HEADERS& ntHeader);
	};
}