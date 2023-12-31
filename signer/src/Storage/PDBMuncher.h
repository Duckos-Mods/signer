#pragma once
#include <dia2.h>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map> // For std::unordered_map

namespace Signer
{
	struct FunctionArgument
	{
		std::wstring name;
		std::wstring type;
	};

	struct Function
	{
		std::wstring name;
		std::wstring returnType;
		unsigned __int64 address;
		unsigned __int64 virtualAddress;
		std::vector<FunctionArgument> arguments;
		unsigned __int64 length;
	};

	class PDBMuncher
	{
	public:
		PDBMuncher(const wchar_t* pdbPath, bool maintainFunctionMap = false);
		~PDBMuncher();

		// Returns a non owning pointer to the global symbols
		std::weak_ptr<std::vector<Function>> GetFunctions() const {return std::make_shared<std::vector<Function>>(m_functions);}

		// Returns a non owning pointer to the global symbols map
		std::weak_ptr<std::unordered_map<std::wstring, Function>> GetFunctionMap() const { return std::make_shared<std::unordered_map<std::wstring, Function>>(m_functionMap); }

		// Parsers
		void MunchFunctions(__int64 virtualOffset);

	private:
		// COM interfaces
		IDiaDataSource* m_pSource = nullptr;
		IDiaSession* m_pSession = nullptr;
		IDiaSymbol* m_pGlobal = nullptr;

		// Utility variables
		const wchar_t* m_pdbPath;
		std::vector<Function> m_functions;
		std::unordered_map<std::wstring, Function> m_functionMap;
		bool m_MaintainFunctionMap = false;
	private:

	};
}