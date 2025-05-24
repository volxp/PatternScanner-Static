#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

namespace PatternScanner {
    struct PatternResult {
        size_t offset;
        bool found;  
        PatternResult() : offset(0), found(false) {}
        PatternResult(size_t off) : offset(off), found(true) {}
    };


    struct MultiPatternResult {
        std::vector<size_t> offsets;
        size_t count;
        
        MultiPatternResult() : count(0) {}
    };
    PatternResult FindPatternInBin(const uint8_t* data, size_t dataSize, 
                                   const std::string& pattern, size_t startOffset = 0);
    PatternResult FindPatternInBin(const std::vector<uint8_t>& data, 
                                   const std::string& pattern, size_t startOffset = 0);
    MultiPatternResult FindAllPatternsInBin(const uint8_t* data, size_t dataSize,
                                             const std::string& pattern, size_t startOffset = 0);
    MultiPatternResult FindAllPatternsInBin(const std::vector<uint8_t>& data,
                                             const std::string& pattern, size_t startOffset = 0);
    namespace Utils {
        std::vector<std::optional<uint8_t>> ParsePattern(const std::string& pattern);
        std::vector<uint8_t> LoadBinaryFile(const std::string& filename);
        std::string BytesToHexString(const uint8_t* data, size_t size);
        bool IsValidPattern(const std::string& pattern);
    }
    class PatternScannerException : public std::exception {
    private:
        std::string message;
    public:
        PatternScannerException(const std::string& msg) : message(msg) {}
        const char* what() const noexcept override { return message.c_str(); }
    };

}