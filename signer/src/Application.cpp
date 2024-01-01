#include "../Logger/Logger.h"
#include <thread> // To get the max ammount of threads that the system can run
#include <mutex>
#include <nlohmann/json.hpp>
#include "Application.h"



Application::Application(int argc, char* argv[])
{
	Logs::Logger::Info(R"(
Welcome to Signer! 
This application is designed to allow for easy transfer function signatures between the Bedrock MCPE BDS and the MCPE Client.
This application is not affiliated with Mojang Studios or Microsoft.
- Duckos
)");
	this->argHandler.addArg(
		new SAH::SAHArg(
			"--MP",
			"Specifies the path to the MCPE binary",
			"string",
			true
		)
	);

	this->argHandler.addArg(
		new SAH::SAHArg(
			"--PSP",
			"Specifies the path to the precomputed signature json",
			"string",
			false,
			std::any(static_cast<std::string>("NIL"))
		)
	);

	this->argHandler.addArg(
		new SAH::SAHArg(
			"--DS",
			"Specifies if the program should do a deep search",
			"bool",
			false,
			std::any(static_cast<bool>(true))
		)
	);

	this->argHandler.addArg(
		new SAH::SAHArg(
			"--NBTC",
			"Specifies the number of threads to use for the non-brute force search",
			"int",
			false,
			std::any(static_cast<int>(1))
		)
	);

	Logs::Logger::Info("Parsing arguments");
	this->argHandler.parseArgs(argc, argv);

	this->mcpePath = this->argHandler.getArgString("--MP");
	this->precomputedSignaturesPath = this->argHandler.getArgString("--PSP");
	this->deepSearch = this->argHandler.getArgBool("--DS");
	this->nonBruteForceThreads = this->argHandler.getArgInt("--NBTC");

	Logs::Logger::Info("MP path : {}", mcpePath);
	Logs::Logger::Info("PSP path : {}", precomputedSignaturesPath);
	Logs::Logger::Info("DS : {}", deepSearch);

	start();
}

void Application::start()
{
	Logs::Logger::Info("Loading MCPE binary");
	this->mcpe = new Signer::MCPEPE(this->mcpePath.c_str());
	if (this->precomputedSignaturesPath != "NIL")
	{
		Logs::Logger::Info("Loading precomputed signatures");
		mcpe->loadFromSigJson(this->precomputedSignaturesPath.c_str());
	}

	NBSP();

	writeWorkingSignatures();
}

void Application::NBSP()
{
	this->workerPool = new BS::thread_pool(this->nonBruteForceThreads);
	auto lambda = [&](size_t localIndex) -> void
		{
			// Get the signature
			auto& signature = this->mcpe->m_bdsSigs[localIndex];
			// Scan for the signature
			auto locatedAddresses = this->scan(signature.second, this->deepSearch);
			if (locatedAddresses.size() == 0)
			{
				// Logs::Logger::Warning("Signature {} was not found in the MCPE binary", signature.first);
				bruteForceContendersMutex.lock();
				bruteForceContenders.push_back(localIndex);
				bruteForceContendersMutex.unlock();
				return;
			}
			if (locatedAddresses.size() > 1)
			{
				Logs::Logger::Warning("Signature {} was found at multiple locations in the MCPE binary", signature.first);
				multiHitSignaturesMutex.lock();
				multiHitSignatures.push_back(localIndex);
				multiHitSignaturesMutex.unlock();
				return;
			}
			// Found a single hit
			std::stringstream locatedAddressHex;
			locatedAddressHex << std::hex << locatedAddresses[0] + 0xC00; // I think i just add that and it works 
			this->mcpe->m_bdsSigs[localIndex].second.setOffset(locatedAddresses[0] + 0xC00);
			Logs::Logger::Info("Signature {} was found at 0x{}", signature.first, locatedAddressHex.str());
			workingSignaturesMutex.lock();
			workingSignatures.push_back(localIndex);
			workingSignaturesMutex.unlock();
		};

	Logs::Logger::Info("Starting non-brute force search");
	for (size_t i = 0; i < this->mcpe->m_bdsSigs.size(); i++)
	{
		auto call = [=]() -> void
			{
				lambda(i);
			};
		this->workerPool->detach_task(call);
	}
	Logs::Logger::Info("Waiting for non-brute force search to finish");
	this->workerPool->wait();
	delete this->workerPool;
	Logs::Logger::Info("Non-brute force search finished with {}/{} signatures found. {} signatures were not found and {} signatures were found at multiple locations", workingSignatures.size(), this->mcpe->m_bdsSigs.size(), bruteForceContenders.size(), multiHitSignatures.size());
}

void Application::BFSP()
{
}

void Application::writeWorkingSignatures()
{
	Logs::Logger::Info("Writing working signatures to file");
	nlohmann::json wj;
	for (auto& index : workingSignatures)
	{
		// End structure should be "symbol" : [sig, offset]
		auto& signature = this->mcpe->m_bdsSigs[index];

		nlohmann::json array = { signature.second.toString(), signature.second.getOffset() };
		wj[signature.first] = array;
	}
	std::ofstream o("workingSignatures.json");
	o << std::setw(4) << wj << std::endl;
	o.close();

}

std::vector<ULONGLONG> Application::scan(Signer::SimpleSig& signature, bool deepSearch, size_t /*Unused*/)
{
	std::vector<ULONGLONG> locatedAddresses; // The addresses that the signature was found at
	// The signature data, mask, and size
	auto* sigData = signature.getSignature();
	size_t sigSize = signature.getLength();
	auto* sigMask = signature.getMask();

	// Mem slice of the MCPE binary
	BoundedSlice<BYTE> mcpeSlice(
		*const_cast<const std::vector<BYTE>*>(&this->mcpe->m_PEData),
		0,
		sigSize-1,
		this->mcpe->m_PEData.size()
	);
	
	// size_t currentEndOffset = sigSize - 1; // The current end offset of the signature

	while (mcpeSlice.getEnd() != this->mcpe->m_PEData.size())
	{
		for (size_t i = 0; i < sigSize; i++)
		{
			if ((*sigMask)[i])
				continue; // Found a wildcard, skip this byte
			if ((*sigData)[i] != mcpeSlice[i])
			{
				mcpeSlice.slide(1);
				break; // No reason to continue if the current byte doesn't match
 			}
			if (i == sigSize - 1)
			{
				// Found a match
				locatedAddresses.push_back(mcpeSlice.getStart());
				mcpeSlice.slide(sigSize-1);
				if (!deepSearch)
					return locatedAddresses;
			}
			
		}
	}

	return locatedAddresses;
}

Signer::SimpleSig Application::trimScan(Signer::SimpleSig& signature, size_t offset)
{
	return Signer::SimpleSig("");
}
