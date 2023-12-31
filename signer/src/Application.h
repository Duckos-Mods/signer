#pragma once
#include <iostream>
#include "SAH.h"
#include "Storage/MCPEEExecuteable.h"
#include "Storage/BDSE.h"
#include <BS_thread_pool.hpp> 

class Application
{
private:
	SAH::SAHArgHandler argHandler;
	Signer::MCPEPE* MCPEDxeData;
	Signer::BDSEPE* BDSEData;

	BS::thread_pool* pool;
	std::vector<ULONGLONG> failOverSignatures;
	std::vector<ULONGLONG> workingSignatures;
public:
	Application(int argc, char* argv[]);
private:
	void start();

	// Non brute force signature pass
	void NBSP();

	// Brute force signature pass 
	void BFSP();

	// Writers

	void writeWorkingSignatures();
	/**
		* @brief Scans the given slice for the signature
		* @param deepSearch If true, the scanner will scan the whole data, otherwise it will return the first occurence
		*/
	ULONGLONG scan(Signer::SimpleSig& signature, bool deepSearch = false, size_t offset = 0);

	Signer::SimpleSig trimScan(Signer::SimpleSig& signature, size_t offset = 0);
};

