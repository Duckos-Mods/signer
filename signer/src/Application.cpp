#include "Application.h"
#include "../Logger/Logger.h"
#include <thread> // To get the max ammount of threads that the system can run
#include <mutex>
#include <nlohmann/json.hpp>

size_t g_devideAmount = 2;
size_t g_trimMinSize = 14;

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
            "--BDSP",
            "The path to the Bedrock Dedicated Server PDB file. required",
            "string",
            true
        )
    );
    this->argHandler.addArg(
		new SAH::SAHArg(
			"--MCPEE",
			"The path to the client executable. required",
			"string",
			true
		)
	);
    this->argHandler.addArg(
        new SAH::SAHArg(
            "--BDSE",
            "The path to the Bedrock Dedicated Server executable. required",
            "string",
            true
        )
    );
    this->argHandler.addArg(
        new SAH::SAHArg(
            "--NBTC",
            "The ammount of threads to use when running a no brute force pass of the binaries",
            "int",
            false,
            std::any(static_cast<int>(std::thread::hardware_concurrency() - 1))
        )
    );
    this->argHandler.addArg(
        new SAH::SAHArg(
            "--BTC",
            "The ammount of threads to use when running a brute force pass of the binaries",
            "int",
            false,
            std::any(static_cast<int>(std::thread::hardware_concurrency() - 1))
        )
	);
    this->argHandler.addArg(
        new SAH::SAHArg(
            "--DA",
            "The Ammount to devide by to calculate the center in the BFSP",
            "int",
            false,
            std::any(static_cast<int>(2))
        )
	);
    this->argHandler.addArg(
        new SAH::SAHArg(
            "--SP",
            "The path to the signature list from the PDB",
            "string",
            false,
            std::any(static_cast<std::string>("NIL"))
        )
    );

    this->argHandler.parseArgs(argc, argv);

    // print args 
    Logs::Logger::Info("Arguments:"); 
    Logs::Logger::Info("BDSP: {}", this->argHandler.getArgString("--BDSP"));
    Logs::Logger::Info("MCPEE: {}", this->argHandler.getArgString("--MCPEE"));
    Logs::Logger::Info("BDSE: {}", this->argHandler.getArgString("--BDSE"));
    Logs::Logger::Info("NBTC: {}", this->argHandler.getArgInt("--NBTC"));
    Logs::Logger::Info("BTC: {}", this->argHandler.getArgInt("--BTC"));
    Logs::Logger::Info("SP: {}", this->argHandler.getArgString("--SP"));
    Logs::Logger::Info("DA: {}", this->argHandler.getArgInt("--DA"));
    g_devideAmount = this->argHandler.getArgInt("--DA");
    start();
}

void Application::start()
{
    auto MCPEPathTemp = this->argHandler.getArgString("--MCPEE");
    this->MCPEDxeData = new Signer::MCPEPE(MCPEPathTemp.c_str());
    Logs::Logger::Info("MCPEPE Loaded!");
    if (this->argHandler.getArgString("--SP") != "NIL")
    {
        Logs::Logger::Info("Loading Signatures!");
		this->MCPEDxeData->loadFromSigJson(this->argHandler.getArgString("--SP").c_str());
		Logs::Logger::Info("Loaded Signatures!");
    }
    else
    {
        auto BDSPathTemp = this->argHandler.getArgString("--BDSE");
        auto BDSPDBTemp = this->argHandler.getArgString("--BDSP");
        this->BDSEData = new Signer::BDSEPE(BDSPathTemp.c_str(), BDSPDBTemp.c_str());
        Logs::Logger::Info("BDSEPE Loaded!");
        // this->MCPEDxeData->setSigJson(this->BDSEData->getSigJson());
    }

    NBSP();
    BFSP();


    writeWorkingSignatures();
    Logs::Logger::Info("Parsed MCPE and BDS PE files");
}

void Application::NBSP()
{
    auto NBSPLambda = [&](Signer::SimpleSig& sig, ULONGLONG index) -> void {
            auto findCount = scan(sig, false, 0);
            if (findCount == 1)
            {
                Logs::Logger::Info("Found Signature: {} symbol: {}", MCPEDxeData->m_bdsSigs[index].first);
                workingSignatures.push_back(index);
            }
			else if (findCount > 1)
			{
				Logs::Logger::Warning("Found Signature: {} symbol: {} {} times", MCPEDxeData->m_bdsSigs[index].first, findCount);
                failOverSignatures.push_back(index);
			}
			else
			{
				//Logs::Logger::Warning("Failed to find Signature: {} symbol: {}", MCPEDxeData->m_bdsSigs[index].first);
                failOverSignatures.push_back(index);
            }
        };

    // Init the thread pool
    this->pool = new BS::thread_pool(this->argHandler.getArgInt("--NBTC"));

    Logs::Logger::Info("Filling NBSP pool");

    // Run the thread pool
    for (ULONGLONG i = 0; i < MCPEDxeData->m_bdsSigs.size(); i++)
    {
        auto sig = MCPEDxeData->m_bdsSigs[i];
        pool->detach_task([i, sig, &NBSPLambda]() {
            NBSPLambda(*const_cast<Signer::SimpleSig*>(&sig.second), i);  // Change the capture of `i` to capture by value
            });
    }


    Logs::Logger::Info("Waiting for thread pool to finish");
    // Wait for the thread pool to finish
    pool->wait();

    Logs::Logger::Info("Finished NBSP pool, {} Functions have the same signature.", this->workingSignatures.size());

    delete pool;
}

void Application::BFSP()
{
    // Init the thread pool
    this->pool = new BS::thread_pool(this->argHandler.getArgInt("--BTC"));

    Logs::Logger::Info("Filling BFSP pool");
    std::mutex mtx;
    for (auto index : this->failOverSignatures)
    {
        pool->detach_task(
            [&, index]() {
                //Signer::SimpleSig sign = ;
                auto sig = trimScan(MCPEDxeData->m_bdsSigs[index].second, 0);
                if (sig.isNull())
                {
					Logs::Logger::Warning("Failed to trim Signature: {}", MCPEDxeData->m_bdsSigs[index].first);
					return;
                }
                mtx.lock();
                MCPEDxeData->m_bdsSigs[index].second = sig;
                workingSignatures.push_back(index);
                mtx.unlock();
                Logs::Logger::Info("Created Trimmed Signature: {} symbol: {}", MCPEDxeData->m_bdsSigs[index].first, sig.toString());
                
            }
        );
    }
    pool->wait();
    Logs::Logger::Info("Waiting for thread pool to finish");
}

void Application::writeWorkingSignatures()
{
    // We wont invoke a real json lib it will just be faster to manualy write it
    std::ofstream jsonFile;
    jsonFile.open("Signatures.json");
    jsonFile << "{\n";
    for (auto& index : this->workingSignatures)
	{
		jsonFile << "\t\"" << MCPEDxeData->m_bdsSigs[index].first << "\": \"" << MCPEDxeData->m_bdsSigs[index].second.toString() << "\",\n";
	}
    // set the last comma to a }
    jsonFile.seekp(-3, std::ios_base::end);
    jsonFile << "\n}";
    jsonFile.close();
    Logs::Logger::Info("Finished writing to JsonFile!");
}

ULONGLONG Application::scan(Signer::SimpleSig& signature, bool deepSearch, size_t offset)
{
    auto& data = MCPEDxeData->m_PEData;
    BoundedSlice<BYTE> memslice(
        data,
        offset,
        offset + signature.getLength(),
        data.size());
    size_t sliceEndIndex = offset + signature.getLength();
    ULONGLONG foundCount = 0;
    // Logs::Logger::Info("Mask: {}", maskToString());
    auto* mask = signature.getMask();
    while (true)
    {
        for (int sigIndex = 0; sigIndex < signature.getLength(); sigIndex++)
        {
            if (sliceEndIndex == data.size())
                return foundCount;

            if ((*mask)[sigIndex])
                continue;

            if (signature[sigIndex] != memslice[sigIndex])
            {
                memslice.slide(1);
                sliceEndIndex++;
                break;
            }

            if (sigIndex == signature.getLength() - 1)
            {
                foundCount++;
                if (!deepSearch)
                    return 1;
            }
        }
    }
}

Signer::SimpleSig Application::trimScan(Signer::SimpleSig& signature, size_t offset)
{
    // If sig is shorter than g_trimMinSize return a null signature

    if (signature.getLength() < g_trimMinSize)
    {
        Logs::Logger::Warning("Signature: {} is too short to trim, This may be changed by a flag --TMS this can make the scans take hours longer though", signature.toString());
        return Signer::SimpleSig("");
    }

    auto* sigData = signature.getSignature();
    auto* mask = signature.getMask();

    auto& data = MCPEDxeData->m_PEData;
    // Calculate the center of the signature
    size_t center = signature.getLength() / g_devideAmount;

    // Create a mem slice of the signature from the start to the center
    BoundedSlice<BYTE> sigSlice(
		*sigData, 
		0,
		center,
		signature.getLength());

    // Create the mem slice of client data 
    BoundedSlice<BYTE> memslice(
        data,
        offset,
        offset + signature.getLength(),
        data.size());

    // Scan for the half signature and cache the starting address of every match
    std::vector<size_t> matches;

    size_t sliceEndIndex = offset + signature.getLength();
    while (true)
    {
        for (size_t splitIndex = 0; splitIndex < center; splitIndex++)
        {
			if (sliceEndIndex == data.size())
                goto LOOPJUMP;
            if (splitIndex == center - 1)
            {
                matches.push_back(sliceEndIndex - signature.getLength());
                // Slide the memslice to the next byte to continue the search
                memslice.slide(1);
                sliceEndIndex++;
                break;
            }
			if ((*mask)[splitIndex])
				continue;

			if (sigSlice[splitIndex] != memslice[splitIndex])
			{
				memslice.slide(1);
				sliceEndIndex++;
				break;
			}

			if (splitIndex == center - 1)
			{
				matches.push_back(sliceEndIndex - signature.getLength());
                // Slide the memslice to the next byte to continue the search
                memslice.slide(1);
                sliceEndIndex++;
            }
        }
    }

    LOOPJUMP:
    // If we have no matches return a null signature
    if (matches.size() == 0)
		return Signer::SimpleSig("");

    // Now we begin the process of trimming the signature
    while (true)
    {
        // Reclaim one byte from sig slice
        sigSlice.setEnd(sigSlice.getEnd() + 1);
        for (int i = 0; i < matches.size(); i++)
        {
            size_t matchBegin = matches[i];
            // walk from the match begin to the end of the signature and check if the signature matches
            for (size_t sigIndex = 0; sigIndex < sigSlice.getEnd(); sigIndex++)
            {
                // We have hit a mask byte so we can skip this byte
                if ((*mask)[sigIndex])
                    continue;

                if (sigSlice[sigIndex] != data[matchBegin + sigIndex])
                {
                    // We have hit a byte that does not match so we can remove this match
                    matches.erase(matches.begin() + i);
                    break;
                }
            }

        }

        if (sigSlice.getEnd() == signature.getLength())
            return Signer::SimpleSig(""); // Returns a null signature if we have trimmed the signature to nothing
        // If we have no matches return a null signature
        if (matches.size() == 0)
            return Signer::SimpleSig("");
        // If we have only one match return the signature
        if (matches.size() == 1) {
            std::vector<BYTE> trimmedSigData;
            for (size_t sigIndex = 0; sigIndex < sigSlice.getEnd(); sigIndex++)
			{
                BYTE val = sigSlice.atClone(sigIndex);
				trimmedSigData.push_back(val);
			}
            Signer::SimpleSig trimmedSig = Signer::SimpleSig(
                trimmedSigData,
                *mask
            );
            return trimmedSig;
        }
    }
}
