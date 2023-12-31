#pragma once
#include <vector>
#include <stdexcept>
#include <string>
#include "Storage/BoundedSlice/BoundedSlice.h"
#include "../Logger/Logger.h"
// Utility names that are used but also defined in windows.h 

#ifndef BYTE
	#define BYTE unsigned char
#endif // !BYTE

#ifndef ULONGLONG
	#define ULONGLONG unsigned long long
#endif // !ULONGLONG


namespace Signer
{
	class nLengthBitMask {
	public:
		void addBitToMask(bool bit) {
			if (maskLength % 8 == 0) {
				maskSegment.push_back(0);
			}
			maskSegment[maskLength / 8] |= bit << (maskLength % 8);
			maskLength++;
		}

		void setBit(size_t index, bool bit = true) {
			if (index >= maskLength) {
				throw std::out_of_range("Index out of range");
			}
			else {
				if (bit) {
					maskSegment[index / 8] |= 1 << (index % 8);
				}
				else {
					maskSegment[index / 8] &= ~(1 << (index % 8));
				}
			}
		}

		bool getBit(size_t index) const {
			if (index >= maskLength) {
				throw std::out_of_range("Index out of range");
			}
			else {
				return maskSegment[index / 8] & (1 << (index % 8));
			}
		}

		bool operator[](size_t index) const {
			return getBit(index);
		}

		size_t getLength() const {
			return maskLength;
		}

		size_t getByteLength() const {
			return (maskLength + 7) / 8; // Round up to nearest byte
		}

	private:
		std::vector<unsigned char> maskSegment;
		size_t maskLength = 0;
	};
	class SimpleSig
	{
	public:
		SimpleSig(const std::string& Startsignature) {
			// convert signature to vector
			for (size_t i = 0; i < Startsignature.length(); i++)
			{
				BYTE lhs = Startsignature[i];
				if (lhs == ' ')
					continue;

				if (lhs == '?')
				{
					mask.addBitToMask(true);
					// push back a padding byte of 0x00
					signature.push_back(0x00);
					continue;
				}

				mask.addBitToMask(false);

				BYTE rhs = Startsignature[++i];

				BYTE combArray[2] = { lhs, rhs };
				signature.push_back((BYTE)strtol((char*)combArray, NULL, 16));
				// Add to i
				i++; // skip next byte because it is already added
			}

			// Just realised this double compiles the mask, Which is causing huge issues
			//CompileSignatureMask();
			this->signatureString = Startsignature;
			return; // Just here so i can set a breakpoint
		}

		SimpleSig(const std::vector<BYTE>& Startsignature) {
			this->signature = signature;
			CompileSignatureMask();
		}

		SimpleSig(const std::vector<BYTE>& signature, const nLengthBitMask& mask) : signature(signature), mask(mask) {}

		/**
		* @brief Scans the given slice for the signature
		* @param deepSearch If true, the scanner will scan the whole data, otherwise it will return the first occurence
		*/
		ULONGLONG inline scan(const std::vector<BYTE>& data,bool deepSearch = false, size_t offset = 0) const {
			BoundedSlice<BYTE> memslice(
				data,
				offset,
				offset + signature.size(),
				data.size());
			size_t sliceEndIndex = offset + signature.size();
			ULONGLONG foundCount = 0;
			// Logs::Logger::Info("Mask: {}", maskToString());
			while (true)
			{
				for (int sigIndex = 0; sigIndex < signature.size(); sigIndex++)
				{
					if (sliceEndIndex == data.size())
						return foundCount;

					if (mask[sigIndex])
						continue;

					if (signature[sigIndex] != memslice[sigIndex])
					{
						memslice.slide(1);
						sliceEndIndex++;
						break;
					}

					if (sigIndex == signature.size() - 1)
					{
						foundCount++;
						if (!deepSearch)
							return 1;
					}
				}
			}
		}

		std::string toString() const
		{
			return signatureString;
		}

		std::string maskToString() const
		{
			std::stringstream result;
			for (size_t i = 0; i < mask.getLength(); i++)
			{
				result << " ";

				if (mask[i])
				{
					result << "?";
				}
				else
				{
					result << "x";
				}
			}

			return result.str();
		}

	private:
		void inline CompileSignatureMask()
		{
			for (auto byte : signature)
			{
				if (byte == '?')
					mask.addBitToMask(true);
				else
					mask.addBitToMask(false);
			}
		}
	private:
		std::vector<BYTE> signature;
		nLengthBitMask mask;
		std::string signatureString;
	};
}