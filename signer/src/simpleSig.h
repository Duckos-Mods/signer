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
			return; // Just here so i can set a breakpoint
		}

		SimpleSig(const std::vector<BYTE>& Startsignature) {
			this->signature = signature;
			CompileSignatureMask();
		}

		SimpleSig(const std::vector<BYTE>& signature, const nLengthBitMask& mask) : signature(signature), mask(mask) {
		}
		SimpleSig(std::vector<BYTE>& signature, nLengthBitMask& mask) : signature(signature), mask(mask) {
		}

		std::string toString() const
		{
			std::stringstream result;
			for (size_t i = 0; i < signature.size(); i++)
			{
				if (i != 0)
					result << " ";

				if (mask[i])
				{
					result << "?";
				}
				else
				{
					// Convert to hex with padded for 00 if needed
					result << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << (int)signature[i];
				}
			}
			return result.str();
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

		// Getters
		std::vector<BYTE>* getSignature() { return &signature; }
		nLengthBitMask* getMask()  { return &mask; }
		size_t getLength() const { return signature.size(); }
		bool isNull() const { return signature.empty(); }

		// [] operator
		BYTE operator[](size_t index) const {
			return signature[index];
		}

		void setOffset(size_t offset) {
			this->offset = offset;
		}

		size_t getOffset() const {
			return offset;
		}

		void setSignatureDataNoMask(const std::vector<BYTE>& signature) {
			this->signature = signature;
		}

		void setMaskNoSignature(const nLengthBitMask& mask) {
			this->mask = mask;
		}

		void setArguments(std::vector<std::string>& arguments) {
			this->arguments = arguments;
			this->argumentCount = arguments.size();
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
		size_t offset = 0;
		int argumentCount = -1;
		std::vector<std::string> arguments;
	};
}