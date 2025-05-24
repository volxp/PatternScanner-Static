#include "CustomPatternLib/lib.hpp"
#include <iostream>
#include <spdlog/spdlog.h>
#include <vector>
#include <unordered_set>
#include <fstream>








namespace functions {
    void mainthread() {
        try {
            auto fileData = PatternScanner::Utils::LoadBinaryFile("RobloxPlayerBeta.exe");

            std::map<std::string, std::string> patterns = {
                {"DecryptLuaState", "8B C1 33 01 33 49 ?? 89 4C 24 ?? 89 44 24 ?? 48 8B 44 24 ?? C3"},
                {"FireClickDetector", "48 89 5C 24 ?? 55 56 57 48 83 EC ?? 49 8B F8 48 8B F1 33 ED 89 AC 24 ?? ?? ?? ?? F3 0F 10 81 ?? ?? ?? ?? 0F 2F C1 0F 86"},
                {"FireMouseClick", "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 79 ?? 41 0F B6 F1"},
                {"FireProximityPrompt", "48 83 EC ?? 48 81 F9 ?? ?? ?? ?? 72"},
                {"FireRightMouseClick", "48 89 5C 24 ?? 55 56 57 48 83 EC ?? 49 8B F8 48 8B F1 33 ED 89 AC 24 ?? ?? ?? ?? F3 0F 10 81 ?? ?? ?? ?? 0F 2F C1 CC"},
                {"FireTouchInterest", "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 79 ?? 41 0F B6 F1"},
                {"GetAssemblyPrimitive", "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 41 ?? 48 85 C0"},
                {"GetContextObject", "48 89 54 24 ?? 48 83 EC ?? 4C 8B D1 44 0F B6 CA"},
                {"GetFFlag", "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 4C 24 ?? 55 57 41 54 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 4C 8B 35"},
                {"GetGlobalState", "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B FA 48 8B D9 49 8B 08"},
                {"GetProperty", "40 57 48 8B 39 4C 8B 41 ?? 49 3B F8 75 ?? 45 33 C9 41 8B C9"},
                {"GetValue", "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 45 0F B6 D1"},
                {"IdentityStruct", "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 90"},
                {"Impersonator", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 49 8B E9"},
                {"LuaC_step", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 48 8B 59 ?? B8"},
                {"LuaD_throw", "48 83 EC ?? 44 8B C2 48 8B D1 48 8D 4C 24"},
                {"LuaL_register", "48 89 5C 24 ?? 4C 89 44 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E8 4C 8B E2"},
                {"LuaVM_Load", "4C 89 44 24 ?? 48 89 4C 24 ?? 53 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 41 8B F9"},
                {"Luau_Execute", "80 79 06 00 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? ??"},
                {"MouseHoverEnter", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 33 ED 89 AC 24 ?? ?? ?? ?? 48 85 D2"},
                {"MouseHoverLeave", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 33 ED 89 AC 24 ?? ?? ?? ?? 48 8B 01"},
                {"Print", "48 89 54 24 ?? 4C 89 44 24 ?? 4C 89 4C 24 ?? 55 53 56 57 41 54 41 55"},
                {"Pseudo2addr", "41 B9 ?? ?? ?? ?? 4C 8B C1 41 3B D1"},
                {"PushInstance", "48 89 5C 24 08 57 48 83 EC ?? 48 8B FA 48 8B D9 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B D7 48 8B CB 48 8B 5C 24 30"},
                {"RaiseEventInvocation", "48 89 5C 24 ?? 55 56 57 48 83 EC ?? 49 8B F1 49 8B E8 48 8B FA 48 8B D9 48 83 79"},
                {"RequestCode", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B EA 48 8B F9 48 85 D2"},
                {"Require", "0F B6 86 ?? ?? ?? ?? 48 89 2F"},
                {"ScriptContextResume", "48 8B C4 44 89 48 ?? 4C 89 40 ?? 48 89 50 ?? 48 89 48 ?? 53"},
                {"SetProtoCapabilities", "48 89 5C 24 ?? 48 89 6C 24 ?? 56 48 83 EC ?? 33 DB"},
                {"TaskDefer", "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 81 EC ?? ?? ?? ?? 48 8B F9 80 3D"},
                {"TaskSpawn", "48 89 5C 24 ?? 55 56 57 48 81 EC ?? ?? ?? ?? 48 8B D9 80 3D"},
                {"luaA_toobject", "48 83 EC ?? 4C 8D 15 ?? ?? ?? ?? 85 D2"},
                {"luaL_checklstring", "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 63 FA 49 8B F0"},
                {"luaM_visitgco", "40 56 41 54 41 55 48 83 EC"},
                {"RawScheduler", "48 89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? EB ?? 48 8B 08 8B 04 0B"}
            };

            for (const auto& [name, pattern] : patterns) {
                auto result = PatternScanner::FindPatternInBin(fileData, pattern);
                if (result.found) {
                    spdlog::info("{} : 0x{:X}", name, result.offset);
                }
                else {
					spdlog::error("{} : Not found", name);
                }
            }
        }
        catch (...) {}
    }

}



int main() {
    functions::mainthread();
    spdlog::warn("Dump Completed.");
    std::cin.get();

    return 0;
}