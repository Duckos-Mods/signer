#pragma once
#include <iostream>
#include "SAH.h"
#include "Storage/MCPEEExecuteable.h"
#include "Storage/BDSE.h"
#include <BS_thread_pool.hpp> 
#include <mutex>

class Application
{
private:
	// Internal data
	SAH::SAHArgHandler argHandler;
	Signer::MCPEPE* mcpe;
	BS::thread_pool* workerPool;

	std::mutex workingSignaturesMutex;
	std::mutex workingTrimmedSignaturesMutex;
	std::mutex bruteForceContendersMutex;
	std::mutex multiHitSignaturesMutex;
	std::mutex nonAlignedSignaturesMutex;
private:
	// Finished Signature scans
	std::vector<ULONGLONG> workingTrimmedSignatures;
	std::vector<ULONGLONG> workingSignatures;
	std::vector<ULONGLONG> bruteForceContenders;
	std::vector<ULONGLONG> multiHitSignatures;
	std::vector<ULONGLONG> nonAlignedSignatures;
private:
	// Arguments
	std::string mcpePath;
	std::string precomputedSignaturesPath;
	bool deepSearch = false;
	int nonBruteForceThreads = 1;
	int divisionFactor = 2;
public:
	Application(int argc, char* argv[]);
	~Application()
	{
		Logs::Logger::close();
	}
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
	std::vector<ULONGLONG> scan(Signer::SimpleSig& signature, bool deepSearch = false, size_t offset = 0);

	Signer::SimpleSig trimScan(Signer::SimpleSig& signature, size_t offset = 0);
};

