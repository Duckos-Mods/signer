#include "MCPEEExecuteable.h"
#include "../../Logger/Logger.h"

namespace Signer
{
	void MCPEPE::loadFromSigJson(const char* path)
	{
		// Invoke Nlohmann::Json to parse the json file
		nlohmann::json json;
		std::ifstream file(path);
		if (!file.is_open())
			Logs::Logger::Error("Failed to open {}", path);

		file >> json;
		file.close();

		// For each key value pair in the json file
		for (auto& [key, value] : json.items())
		{
			SimpleSig sig(value.get<std::string>());
			std::pair<std::string, SimpleSig> pair(key, sig);
			this->m_bdsSigs.push_back(pair);
		}
		Logs::Logger::Info("Loaded {} signatures from {}", this->m_bdsSigs.size(), path);
	}
}