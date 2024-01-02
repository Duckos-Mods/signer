#include "PEParser.h"
#include <fstream>
#include "../../Logger/Logger.h"
#include <tuple>
namespace Signer
{
	std::pair<void*, unsigned long> PEParser::LoadFile(const char* path)
	{
		std::ifstream file(path, std::ios::binary);

		if (!file.is_open())
			Logs::Logger::Error("PEParser::LoadFile: Failed to open file: {}", path);

		file.seekg(0, std::ios::end);
		// We are going to use a c style array to store the file data
		// so we need to know the size of the file to allocate the array
		std::streampos size = file.tellg();
		file.seekg(0, std::ios::beg);

		void* buffer = malloc(size);
		file.read((char*)buffer, size);
		file.close();

		return { buffer, size };

	}
	bool PEParser::ParsePE(const char* path, std::vector<BYTE>* data, PIMAGE_NT_HEADERS& ntHeader)
	{
		auto PEBuffer = LoadFile(path);
		if (PEBuffer.first == nullptr)
			Logs::Logger::Error("PEParser::ParsePE: Failed to load file: {}", path);

		BYTE* buffer = reinterpret_cast<BYTE*>(PEBuffer.first);
		DWORD size = PEBuffer.second;

		// Get dos header
		IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			Logs::Logger::Error("PEParser::ParsePE: Invalid DOS signature: {}", path);

		DWORD peOffset = dosHeader->e_lfanew;

		// Get nt header
		if (peOffset + sizeof(IMAGE_DOS_HEADER) > size)
			Logs::Logger::Error("PEParser::ParsePE: Invalid PE offset: {}", path);

		ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + peOffset);

		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			Logs::Logger::Error("PEParser::ParsePE: Invalid NT signature: {}", path);

		// Grab file offset
		DWORD fileOffset = ntHeader->OptionalHeader.ImageBase;

		// Log the offset in hex
		Logs::Logger::Info(std::format("PEParser::ParsePE: File offset: 0x{0:x}", fileOffset));

		// set data to everything from the nt header end to the end of the file
		//data->resize(size - peOffset);
		data->assign(buffer, buffer + size);

		return true;
	}

}