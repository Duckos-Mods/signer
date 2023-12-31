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
	void NBSP();

	// Writers

	void writeWorkingSignatures();

};

