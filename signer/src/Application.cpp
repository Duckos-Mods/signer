#include "Application.h"
#include "../Logger/Logger.h"
#include <thread> // To get the max ammount of threads that the system can run
#include <mutex>
#include <nlohmann/json.hpp>

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

    Logs::Logger::Info("Parsed MCPE and BDS PE files");
}

void Application::NBSP()
{
    auto NBSPLambda = [&](const Signer::SimpleSig& sig, ULONGLONG index) -> void {
            auto findCount = sig.scan(MCPEDxeData->m_PEData, false, 0);
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
            NBSPLambda(sig.second, i);  // Change the capture of `i` to capture by value
            });
    }


    Logs::Logger::Info("Waiting for thread pool to finish");
    // Wait for the thread pool to finish
    pool->wait();

    Logs::Logger::Info("Finished NBSP pool, {} Functions have the same signature. Writing to JsonFile!", this->workingSignatures.size());

    writeWorkingSignatures();

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
    jsonFile.seekp(-2, std::ios_base::end);
    jsonFile << "\n}";
    jsonFile.close();
    Logs::Logger::Info("Finished writing to JsonFile!");
}
