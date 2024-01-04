#include "../Logger/Logger.h"
#include <thread> // To get the max ammount of threads that the system can run
#include <mutex>
#include <nlohmann/json.hpp>
#include "Application.h"
#include <assert.h>
#include <Dbghelp.h>

// I would never do this usually but i dont care enough right now.
#pragma comment(lib, "Dbghelp.lib")

constexpr DWORD maxSymbolLength = 1024 * 12;

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

	this->argHandler.addArg(
		new SAH::SAHArg(
			"--CDV",
			"Specifies the number to use as the division factor for the brute force search",
			"int",
			false,
			std::any(static_cast<int>(2))
		)
	);
	this->argHandler.addArg(
		new SAH::SAHArg(
			"--EO",
			"Specifies if the program should early out and only dump workingsigs and not trim any",
			"bool",
			false,
			std::any(static_cast<bool>(false))
		)
	);

	Logs::Logger::Info("Parsing arguments");
	this->argHandler.parseArgs(argc, argv);

	this->mcpePath = this->argHandler.getArgString("--MP");
	this->precomputedSignaturesPath = this->argHandler.getArgString("--PSP");
	this->deepSearch = this->argHandler.getArgBool("--DS");
	this->nonBruteForceThreads = this->argHandler.getArgInt("--NBTC");
	this->divisionFactor = this->argHandler.getArgInt("--CDV");

	Logs::Logger::Info("MP path : {}", mcpePath);
	Logs::Logger::Info("PSP path : {}", precomputedSignaturesPath);
	Logs::Logger::Info("DS : {}", deepSearch);
	Logs::Logger::Info("NBTC : {}", nonBruteForceThreads);
	Logs::Logger::Info("CDV : {}", divisionFactor);

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
	if (!this->argHandler.getArgBool("--EO"))
		BFSP();

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
			// Calculate the ammount of arguments the function takes
			char demangled[maxSymbolLength];
			DWORD result = 0;
			// Demangle the symbol
			result = UnDecorateSymbolName(signature.second.toString().c_str(), demangled, maxSymbolLength, UNDNAME_COMPLETE);

			// If the demangle failed we should warn in the console 
			if (result != 0)
			{
				std::vector<std::string> arguments;
				size_t start = 0;
				for (size_t end = 0; end < maxSymbolLength; end++)
				{
					if (demangled[end] == '\0')
					{
						arguments.push_back(std::string(demangled + start, end - start));
						break;
					}
					if (demangled[end] == ',')
					{
						arguments.push_back(std::string(demangled + start, end - start));
						start = end + 1;
					}
				}
			}
			else
			{
				Logs::Logger::Warning("Failed to demangle symbol {}. Maybe a custom signature?", signature.second.toString());
			}
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
	// Init the worker pool
	this->workerPool = new BS::thread_pool(this->nonBruteForceThreads);

	// Store the current working signatures size
	size_t currentWorkingSignaturesSize = workingSignatures.size();

	// Define the lambda
	auto lambda = [&](size_t index) -> void
		{
			// Get sig from sigDump
			auto& signature = this->mcpe->m_bdsSigs[index];

			// Trim scan the signature
			auto trimmedSig = this->trimScan(signature.second, 0);

			// If sig is null we failed to trim scan and should return and warn in the console
			if (trimmedSig.isNull())
			{
				Logs::Logger::Warning("Failed to trim scan for the signature of {}", signature.first);
				return;
			}

			// If sig is not aligned to 0x10 we should warn in the console and push to a new vector
			if (trimmedSig.getOffset() % 0x10 != 0)
			{
				Logs::Logger::Warning("Trimmed signature {} was not aligned to 0x10", signature.first);
				nonAlignedSignaturesMutex.lock();
				nonAlignedSignatures.push_back(index);
				nonAlignedSignaturesMutex.unlock();
				return;
			}

			// We have a trimmed signature so log it and modify the signature in the mcpe object
			std::stringstream locatedAddressHex;
			locatedAddressHex << std::hex << trimmedSig.getOffset();

			// Calculate the ammount of arguments the function takes
			char demangled[maxSymbolLength];
			DWORD result = 0;
			// Demangle the symbol
			result = UnDecorateSymbolName(trimmedSig.toString().c_str(), demangled, maxSymbolLength, UNDNAME_COMPLETE);

			// If the demangle failed we should warn in the console 
			if (result != 0)
			{
				std::vector<std::string> arguments;
				size_t start = 0;
				for (size_t end = 0; end < maxSymbolLength; end++)
				{
					if (demangled[end] == '\0')
					{
						arguments.push_back(std::string(demangled + start, end - start));
						break;
					}
					if (demangled[end] == ',')
					{
						arguments.push_back(std::string(demangled + start, end - start));
						start = end + 1;
					}
				}
			}
			else
			{
				Logs::Logger::Warning("Failed to demangle symbol {}. Maybe a custom signature?", trimmedSig.toString());
			}

			Logs::Logger::Info("Trimmed signature {} was found at 0x{}", signature.first, locatedAddressHex.str());
			this->mcpe->m_bdsSigs[index].second = trimmedSig;

			// Add the index to the working signatures
			workingTrimmedSignaturesMutex.lock();
			workingTrimmedSignatures.push_back(index);
			workingTrimmedSignaturesMutex.unlock();

			// return
			return;
		};

	Logs::Logger::Info("Starting brute force search");
	for (auto& index : bruteForceContenders)
	{
		auto call = [=]() -> void
			{
					lambda(index);
			};
		this->workerPool->detach_task(call);
	}
	Logs::Logger::Info("Waiting for brute force search to finish");
	this->workerPool->wait();
	delete this->workerPool; // Delete the worker pool
	Logs::Logger::Info("Brute force search finished with {}/{} signatures found", workingSignatures.size() - currentWorkingSignaturesSize, bruteForceContenders.size());


}

void Application::writeWorkingSignatures()
{
	Logs::Logger::Info("Writing working signatures to file");
	nlohmann::json wj;
	nlohmann::json ws;
	nlohmann::json mhs;
	nlohmann::json nas;
	nlohmann::json wts;

	for (auto& index : workingSignatures)
	{
		// End structure should be "symbol" : [sig, offset]
		auto& signature = this->mcpe->m_bdsSigs[index];

		nlohmann::json array = { signature.second.toString(), signature.second.getOffset() };
		ws[signature.first] = array;
	}
	wj["workingSignatures"] = ws;


	// Write manual sig fixes
	for (auto& index : this->multiHitSignatures)
	{
		auto& signature = this->mcpe->m_bdsSigs[index];
		mhs[signature.first] = { signature.second.toString(), "MULTI" };
	}
	wj["multiHitSignatures"] = mhs;

	// Write non aligned sigs
	for (auto& index : this->nonAlignedSignatures)
	{
		auto& signature = this->mcpe->m_bdsSigs[index];
		nas[signature.first] = { signature.second.toString(), signature.second.getOffset()};

	}
	wj["nonAlignedSignatures"] = nas;

	// Write working trimmed sigs
	for (auto& index : this->workingTrimmedSignatures)
	{
		auto& signature = this->mcpe->m_bdsSigs[index];
		wts[signature.first] = { signature.second.toString(), signature.second.getOffset() };
	}
	wj["trimmedSignatures"] = wts;

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
	size_t oldEnd = mcpeSlice.getEnd();
	while (mcpeSlice.getEnd() != this->mcpe->m_PEData.size())
	{
		for (size_t i = 0; i < sigSize; i++)
		{
			// Handle the case where the last byte is a wildcard this used to cause a loop
			if (i == sigSize - 1 && (*sigMask)[i])
			{
				// Found a match
				locatedAddresses.push_back(mcpeSlice.getStart());
				mcpeSlice.slide(sigSize - 1);
				if (!deepSearch)
					return locatedAddresses;
				break; // No reason to continue if the current byte doesn't match
			}
			if ((*sigMask)[i])
			{
				continue; // Found a wildcard, skip this byte
			}
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
		if (mcpeSlice.getEnd() == oldEnd)
		{
			mcpeSlice.slide(1);
			Logs::Logger::Warning("Detected a hang in the scan, sliding 1 byte this should not happen dumping log info");
			// Throw a debug breakpoint
			//__debugbreak();
			Logs::Logger::Warning(R"(
Start : {}
End : {}
Size : {}
Signature : {}
Mask : {}
Locatted Addresses Count : {}
Current End Offset : {}
)", mcpeSlice.getStart(), mcpeSlice.getEnd(), mcpeSlice.size(), signature.toString(), signature.maskToString(), locatedAddresses.size(), oldEnd);
		}
		oldEnd = mcpeSlice.getEnd();
	}

	return locatedAddresses;
}

Signer::SimpleSig Application::trimScan(Signer::SimpleSig& signature, size_t offset)
{
	Signer::SimpleSig trimmedSig("");

	if (signature.getLength() < divisionFactor*2)
		return trimmedSig;

	// The signature data, mask, and size
	auto* sigData = signature.getSignature();
	size_t sigSize = signature.getLength();
	auto* sigMask = signature.getMask();

	// Calculate a center point of the signature
	size_t centerPoint = sigSize / divisionFactor;
	// Mem slice over the signature to its left
	BoundedSlice<BYTE> leftSlice(
		*const_cast<const std::vector<BYTE>*>(sigData),
		0,
		centerPoint,
		sigSize
	);

	// Construct a new signature
	// Remove any trailing wildcards
	while (leftSlice.back() == 0x00)
	{
		leftSlice.setEnd(leftSlice.getEnd() + 1);
		if (leftSlice.getEnd() == 0)
			return Signer::SimpleSig("");
	}
	Signer::SimpleSig newSig(leftSlice.getAsVector(), *sigMask);

	while (true)
	{
		// Scan for the new signature
		auto addrs = scan(newSig, true);
		// If there are no hits, return an empty signature
		if (addrs.size() == 0)
			return Signer::SimpleSig("");
		// If there is a single hit, begin testing for validity
		if (addrs.size() == 1)
		{
			// Use std::move to avoid copying the signature
			trimmedSig = std::move(newSig);
			// Set the offset of the signature
			trimmedSig.setOffset(addrs[0] + 0xC00);

			break;
		}

		// Multiple hits, reclaim more of the signature
		leftSlice.setEnd(leftSlice.getEnd() + 1);
		if (leftSlice.getEnd() == sigSize)
			return Signer::SimpleSig("");

		// Set the new signature data
		newSig.setSignatureDataNoMask(leftSlice.getAsVector());
	}
	return trimmedSig;
}
