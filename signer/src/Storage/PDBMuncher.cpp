#include "PDBMuncher.h"
#include "../../Logger/Logger.h"

namespace Signer
{
	PDBMuncher::PDBMuncher(const wchar_t* pdbPath, bool maintainFunctionMap) : m_pdbPath(pdbPath), m_MaintainFunctionMap(maintainFunctionMap)
	{
		// Init the DIA data source
		HRESULT hr = CoInitialize(NULL);
		if (FAILED(hr))
			Logs::Logger::Error("Failed to initialize COM library. Error code: {}", hr);

		hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, IID_IDiaDataSource, (void**)&m_pSource);
		if (FAILED(hr))
		{
			CoUninitialize();
			Logs::Logger::Error("Failed to create DIA data source. Error code: {}", hr);
		}

		// Load the PDB
		hr = m_pSource->loadDataFromPdb(m_pdbPath);
		if (FAILED(hr))
		{
			Logs::Logger::Error("Failed to load PDB. Error code: {}", hr);
			m_pSource->Release();
			CoUninitialize();
		}

		// Open the session and get the global scope
		hr = m_pSource->openSession(&m_pSession);
		if (FAILED(hr))
		{
			Logs::Logger::Error("Failed to open session. Error code: {}", hr);
			m_pSource->Release();
			CoUninitialize();
		}

		hr = m_pSession->get_globalScope(&m_pGlobal);
		if (FAILED(hr))
		{
			Logs::Logger::Error("Failed to get global scope. Error code: {}", hr);
			m_pSession->Release();
			m_pSource->Release();
			CoUninitialize();
		}
		// Reset the HR variable
		hr = S_OK;
	}

	PDBMuncher::~PDBMuncher()
	{
		m_pGlobal->Release();
		m_pSession->Release();
		m_pSource->Release();
		CoUninitialize();
	}

	void PDBMuncher::MunchFunctions(__int64 virtualOffset)
	{
		// get all the functions
		IDiaEnumSymbols* pEnumSymbols = nullptr;
		HRESULT hr = m_pGlobal->findChildren(SymTagFunction, NULL, nsNone, &pEnumSymbols);
		if(FAILED(hr))
			Logs::Logger::Error("Failed to find children. Error code: {}", hr);

		IDiaSymbol* pSymbol = nullptr;
		ULONG celt = 0;
		size_t dataIndex = 0; // Index to track function addresses in the data array

		while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && celt == 1) {
			Function function;
			ULONGLONG address = 0;
			hr = pSymbol->get_virtualAddress(&address);
			if (FAILED(hr)) {
				Logs::Logger::Warning("Failed to get virtual address. Error code: {}", hr);
				continue;
			}
			ULONGLONG realAddress = address - virtualOffset;

			function.virtualAddress = address; // Set the virtual address from the PDB
			function.address = address; // Set the address as the index in the data array

			// Name
			BSTR bstrName;
			hr = pSymbol->get_name(&bstrName);
			if (FAILED(hr))
			{
				Logs::Logger::Warning("Failed to get name. Error code: {}", hr);
				continue;
			}
			function.name = std::wstring(bstrName);

			// Args and return type
			IDiaEnumSymbols* pEnumChildren = nullptr;
			hr = pSymbol->findChildren(SymTagNull, NULL, nsNone, &pEnumChildren);
			if (FAILED(hr)) {
				Logs::Logger::Warning("Failed to find children. Error code: {}", hr);
				continue;
			}

			IDiaSymbol* pChild = nullptr;
			ULONG celtChildren = 0;
			while (SUCCEEDED(pEnumChildren->Next(1, &pChild, &celtChildren)) && celtChildren == 1) {
				BSTR childName;
				hr = pChild->get_name(&childName);
				if (FAILED(hr)) {
					Logs::Logger::Error("Failed to get name. Error code: {}", hr);
					continue;
				}

				// Retrieve type of argument
				IDiaSymbol* pTypeSymbol = nullptr;
				hr = pChild->get_type(&pTypeSymbol);
				if (FAILED(hr)) {
					Logs::Logger::Error("Failed to get type. Error code: {}", hr);
					continue;
				}

				BSTR typeName;
				hr = pTypeSymbol->get_name(&typeName);
				if (FAILED(hr)) {
					Logs::Logger::Error("Failed to get type name. Error code: {}", hr);
					continue;
				}

				// Check if it is a return type
				DWORD symTag;
				hr = pChild->get_symTag(&symTag);
				if (SUCCEEDED(hr) && symTag == SymTagFunctionType) {
					function.returnType = std::wstring(typeName);
				}
				else {
					// Add argument
					FunctionArgument arg;
					arg.name = std::wstring(childName);
					arg.type = std::wstring(typeName);
					function.arguments.push_back(arg);
				}

				pTypeSymbol->Release();
				pChild->Release();
			}

			// Size
			ULONGLONG size = 0;
			hr = pSymbol->get_length(&size);
			if (FAILED(hr)) {
				Logs::Logger::Error("Failed to get size. Error code: {}", hr);
				continue;
			}
			function.length = size;

			if (m_MaintainFunctionMap)
				m_functionMap[function.name] = function;

			m_functions.push_back(function);
			pSymbol->Release();
		}
	}
}