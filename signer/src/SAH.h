#pragma once
#include <string>
#include <typeinfo>
#include <vector>
#include <stdexcept>
#include <any>
#include "../Logger/Logger.h"

// Simple argument handler
namespace SAH
{
	namespace
	{
		bool fastStrCmp(const char* a, const char* b)
		{
			bool breakLoop = false;
			while (!breakLoop)
			{
				if (*a != *b)
					return false;
				// Strings don't match
				else if (*a == '\0' && *b == '\0')
					breakLoop = true;
				// strings do match
				a++;
				b++;
			}

			return true;
		}

		const char* getAsType(char* value)
		{
			// We are going to try and guess the type
			// We will try and convert to int, float, bool, and string
			// in that order

			// Try and convert to int
			try
			{
				int i = std::stoi(value);
				return "int";
			}
			catch (std::invalid_argument)
			{
			}
			// Try and convert to float
			try
			{
				float f = std::stof(value);
				return "float";
			}
			catch (std::invalid_argument)
			{
			}
			// Try and convert to bool
			try
			{
				bool b = std::stoi(value);
				return "bool";
			}
			catch (std::invalid_argument)
			{
			}
			// Try and convert to string
			try
			{
				std::string s = std::string(value);
				return "string";
			}
			catch (std::invalid_argument)
			{
			}
		}

		std::any getAsValue(char* value, const char* type)
		{
			// Jump to the type
			if (fastStrCmp(type, "int"))
			{
				int i = int(std::stoi(value));
				return i;
			}
			else if (fastStrCmp(type, "float"))
			{
				float f = float(std::stof(value));
				return f;
			}
			else if (fastStrCmp(type, "bool"))
			{
				bool b = bool(std::stoi(value));
				return b;
			}
			else if (fastStrCmp(type, "string"))
			{
				std::string s = std::string(value);
				return s;
			}
			else
			{
				// Type not found
				return nullptr;
			}
		}
	}

	class SAHArg
	{
	public:
		SAHArg(
			std::string name,
			std::string description,
			std::string expectedType,
			bool isRequired = false,
			std::any valueByDefault = nullptr
			)
			: m_name(name)
			, m_description(description)
			, m_isRequired(isRequired)
			, m_expectedType(expectedType)
			, m_value(valueByDefault)
		{
		}

		SAHArg() = default;

		// Getters
		std::string getName() const { return m_name; }
		std::string getDescription() const { return m_description; }
		bool isRequired() const { return m_isRequired; }
		std::any getValue() const { return m_value; }

		// Test if tag matches and set value
		bool setArg(char* tag, std::any value)
		{
			// Check if tag matches
			if (!fastStrCmp(tag, m_name.c_str()))
				return false;

			// This is so unsafe
			// Set value
			m_value = value;
			return true;
		}
		const char* getType() const { return m_expectedType.c_str(); }
	private:
		std::string m_name;
		std::string m_description;
		bool m_isRequired;
		std::any m_value;
		std::string m_expectedType;
	};
	
	

	class SAHArgHandler
	{
	public:
		SAHArgHandler() = default;

		~SAHArgHandler()
		{
			// Delete all args
			for (auto arg : m_args)
			{
				delete arg;
			}
		}

		// Add an argument
		bool addArg(SAHArg* arg)
		{
			// Check if arg is valid
			if (arg == nullptr)
				return false;

			for (auto a : m_args)
			{
				// Check if arg already exists
				if (a->getName() == arg->getName())
					return false;
			}

			// Add arg
			m_args.push_back(arg);
			return true;
		}

		// Parse arguments
		void parseArgs(int argc, char** argv)
		{
			for (int i = 1; i < argc - 1; i++)
			{
				// Get tag
				char* tag = argv[i];

				// Loop through args
				for (auto arg : m_args)
				{
					// Check if tag matches
					if (arg->setArg(tag, getAsValue(argv[i + 1], getAsType(argv[i + 1]))))
					{
						// Tag matches
						// Skip next arg
						i++;
						break;
					}
				}
			}

			// Make sure all required args are set
			for (auto arg : m_args)
			{
				// Check if arg is required
				if (arg->isRequired())
				{
					// Check if arg is set
					if (!arg->getValue().has_value())
					{
						// Arg is not set
						// Throw error
						Logs::Logger::Warning("Required argument not set: " + arg->getName());
						goto Help;
					}
				}
			}

			goto end;
		Help:
			// Print help
			Logs::Logger::Info("Help:");
			for (auto arg : m_args)
			{
				Logs::Logger::Warning("{} : {}, type {}", arg->getName(), arg->getDescription(), arg->getType());
			}
		end:
			return;
		}

		std::any getArg(std::string name)
		{
			for (auto arg : m_args)
			{
				if (arg->getName() == name)
					return arg->getValue();
			}

			return nullptr;
		}

		// get args with types
		std::string getArgString(std::string name)
		{
			for (auto arg : m_args)
			{
				if (arg->getName() == name)
					return std::any_cast<std::string>(arg->getValue());
			}

			return "";
		}

        int getArgInt(std::string name)
		{
			for (auto arg : m_args)
			{
				if (arg->getName() == name)
					return std::any_cast<int>(arg->getValue());
			}
			return 0;
		}
		float getArgFloat(std::string name)
		{
			for (auto arg : m_args)
			{
				if (arg->getName() == name)
					return std::any_cast<float>(arg->getValue());
			}
			return 0;
		}
		bool getArgBool(std::string name)
		{
			for (auto arg : m_args)
			{
				if (arg->getName() == name)
					return std::any_cast<bool>(arg->getValue());
			}
			return false;
		}
		// Getters
		std::vector<SAHArg*> getArgs() const { return m_args; }


	private:
		std::vector<SAHArg*> m_args;
	};
}