#include "lib.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace PatternScanner {

    PatternResult FindPatternInBin(const uint8_t* data, size_t dataSize,
        const std::string& pattern, size_t startOffset) {
        if (!data || dataSize == 0) {
            return PatternResult();
        }

        if (!Utils::IsValidPattern(pattern)) {
            throw PatternScannerException("Invalid pattern format");
        }

        auto parsedPattern = Utils::ParsePattern(pattern);
        if (parsedPattern.empty()) {
            return PatternResult();
        }

        size_t patternSize = parsedPattern.size();
        if (startOffset + patternSize > dataSize) {
            return PatternResult();
        }

        // Boyer-Moore-like search with wildcard support
        for (size_t i = startOffset; i <= dataSize - patternSize; ++i) {
            bool match = true;

            for (size_t j = 0; j < patternSize; ++j) {
                if (parsedPattern[j].has_value() &&
                    parsedPattern[j].value() != data[i + j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return PatternResult(i);
            }
        }

        return PatternResult();
    }

    PatternResult FindPatternInBin(const std::vector<uint8_t>& data,
        const std::string& pattern, size_t startOffset) {
        return FindPatternInBin(data.data(), data.size(), pattern, startOffset);
    }

    MultiPatternResult FindAllPatternsInBin(const uint8_t* data, size_t dataSize,
        const std::string& pattern, size_t startOffset) {
        MultiPatternResult result;

        if (!data || dataSize == 0) {
            return result;
        }

        if (!Utils::IsValidPattern(pattern)) {
            throw PatternScannerException("Invalid pattern format");
        }

        auto parsedPattern = Utils::ParsePattern(pattern);
        if (parsedPattern.empty()) {
            return result;
        }

        size_t patternSize = parsedPattern.size();
        if (startOffset + patternSize > dataSize) {
            return result;
        }

        for (size_t i = startOffset; i <= dataSize - patternSize; ++i) {
            bool match = true;

            for (size_t j = 0; j < patternSize; ++j) {
                if (parsedPattern[j].has_value() &&
                    parsedPattern[j].value() != data[i + j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                result.offsets.push_back(i);
                result.count++;
            }
        }

        return result;
    }

    MultiPatternResult FindAllPatternsInBin(const std::vector<uint8_t>& data,
        const std::string& pattern, size_t startOffset) {
        return FindAllPatternsInBin(data.data(), data.size(), pattern, startOffset);
    }

    PatternResult GetLeaFromPattern(const uint8_t* data, size_t dataSize,
        const std::string& pattern, size_t leaOffset,
        uintptr_t imageBase) {
        if (!data || dataSize == 0) {
            return PatternResult();
        }





        auto patternResult = FindPatternInBin(data, dataSize, pattern);
        if (!patternResult.found) {
            return PatternResult();
        }

        size_t instructionAddress = patternResult.offset + leaOffset;
        if (instructionAddress + 7 > dataSize) {
            return PatternResult();
        }

        const uint8_t* instruction = data + instructionAddress;

        if (instruction[0] == 0x48 && instruction[1] == 0x8D) {
            int32_t displacement = *reinterpret_cast<const int32_t*>(&instruction[3]);
            uintptr_t targetAddress = imageBase + instructionAddress + 7 + displacement;
            size_t fileOffset = targetAddress - imageBase;
            if (fileOffset < dataSize) {
                return PatternResult(fileOffset);
            }
        }

        return PatternResult();
    }

    PatternResult GetLeaFromPattern(const std::vector<uint8_t>& data,
        const std::string& pattern, size_t leaOffset,
        uintptr_t imageBase) {
        return GetLeaFromPattern(data.data(), data.size(), pattern, leaOffset, imageBase);
    }

    namespace Utils {

        std::vector<std::optional<uint8_t>> ParsePattern(const std::string& pattern) {
            std::vector<std::optional<uint8_t>> result;
            std::string cleanPattern = pattern;
            cleanPattern.erase(std::remove_if(cleanPattern.begin(), cleanPattern.end(), ::isspace),
                cleanPattern.end());

            if (cleanPattern.length() % 2 != 0) {
                throw PatternScannerException("Pattern length must be even (each byte requires 2 hex characters)");
            }

            for (size_t i = 0; i < cleanPattern.length(); i += 2) {
                std::string byteStr = cleanPattern.substr(i, 2);

                if (byteStr == "??" || byteStr == "XX" || byteStr == "xx") {
                    result.push_back(std::nullopt); // Wildcard
                }
                else {
                    try {
                        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
                        result.push_back(byte);
                    }
                    catch (const std::exception&) {
                        throw PatternScannerException("Invalid hex character in pattern: " + byteStr);
                    }
                }
            }

            return result;
        }

        std::vector<uint8_t> LoadBinaryFile(const std::string& filename) {
            std::ifstream file(filename, std::ios::binary | std::ios::ate);

            if (!file.is_open()) {
                throw PatternScannerException("Cannot open file: " + filename);
            }

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(size);
            if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                throw PatternScannerException("Error reading file: " + filename);
            }

            return buffer;
        }

        std::string BytesToHexString(const uint8_t* data, size_t size) {
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');

            for (size_t i = 0; i < size; ++i) {
                ss << std::setw(2) << static_cast<unsigned>(data[i]);
                if (i < size - 1) ss << " ";
            }

            return ss.str();
        }

        bool IsValidPattern(const std::string& pattern) {
            if (pattern.empty()) return false;

            std::string cleanPattern = pattern;
            cleanPattern.erase(std::remove_if(cleanPattern.begin(), cleanPattern.end(), ::isspace),
                cleanPattern.end());

            if (cleanPattern.length() % 2 != 0) return false;

            for (size_t i = 0; i < cleanPattern.length(); i += 2) {
                std::string byteStr = cleanPattern.substr(i, 2);

                if (byteStr == "??" || byteStr == "XX" || byteStr == "xx") {
                    continue; // Valid wildcard
                }
                for (char c : byteStr) {
                    if (!std::isxdigit(c)) {
                        return false;
                    }
                }
            }

            return true;
        }
    }

}