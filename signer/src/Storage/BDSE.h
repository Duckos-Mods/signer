#pragma once
#include "PEParser.h"
#include "PDBMuncher.h"
#include <codecvt>

namespace Signer
{
	class BDSEPE
	{
	private:
		PIMAGE_NT_HEADERS m_PEHeader;
		std::vector<unsigned char> m_PEData;
		Signer::PDBMuncher* m_PDBMuncher;
	public:
		BDSEPE(const char* exePath, const char* PDBPath = "")
		{
			PEParser::ParsePE(exePath, &m_PEData, m_PEHeader);
			// convert PDBPath to wchar_t*
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			std::wstring wide = converter.from_bytes(PDBPath);
			if (PDBPath != "")
			{
				this->m_PDBMuncher = new Signer::PDBMuncher(wide.c_str());
				m_PDBMuncher->MunchFunctions(m_PEHeader->OptionalHeader.ImageBase);
			}
			else
			{
				this->m_PDBMuncher = nullptr;
			}
		}
	};
}

