#pragma once
#include "PEParser.h"
#include "../simpleSig.h"
#include <tuple>
#include <nlohmann/json.hpp>

namespace Signer
{
	class MCPEPE
	{
	private:
	public:
		MCPEPE(const char* path)
		{
			// Read the file
			PEParser::ParsePE(path, &m_PEData, m_PEHeader);
		}

		void loadFromSigJson(const char* path);
		void inline setSigJson(std::vector<std::pair<std::string, SimpleSig>>& sig) { m_bdsSigs = sig; }

		ULONGLONG getHeaderOffset() { return (ULONGLONG)m_PEHeader - (ULONGLONG)m_PEData.data(); }
	public:
		PIMAGE_NT_HEADERS m_PEHeader;
		std::vector<BYTE> m_PEData;

		std::vector<std::pair<std::string, SimpleSig>> m_bdsSigs;

	};
}