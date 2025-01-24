// Created By User on 1.20.2025 Using Clion
#ifndef DATAMODEL_HPP //i was here
#define DATAMODEL_HPP
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <filesystem>
#include <regex>
#include <optional>
#include <unordered_set>
#include <functional>
#pragma comment(lib, "dbghelp.lib")
#include <wincpp/process.hpp>
struct RTTICompleteObjectLocator {
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    DWORD typeDescriptor;
    DWORD classDescriptor;
    DWORD baseOffset;
};
struct TypeDescriptor {
    void* vtable;
    uint64_t ptr;
    char name[255];
};
std::optional<std::string> getLatestLogFile(const std::string& folderPath);
std::string readFile(const std::string& filePath);
uintptr_t locateThreadId(const std::string& content);
std::string demangleSymbol(const std::string& mangledName);
uintptr_t getModuleBaseAddress(std::unique_ptr<wincpp::process_t>& process, uintptr_t address);
bool isValidAddress(std::unique_ptr<wincpp::process_t>& process, uintptr_t address);
std::optional<std::string> getRTTIName(std::unique_ptr<wincpp::process_t>& process, uintptr_t objectAddress);
uintptr_t getFirstAncestor(std::unique_ptr<wincpp::process_t>& process, uintptr_t address);
uintptr_t findDataModelPointer(std::unique_ptr<wincpp::process_t>& process, uintptr_t threadId);
void disableMemoryWatch(std::unique_ptr<wincpp::process_t>& process);
void recursiveMemoryWalk(std::unique_ptr<wincpp::process_t>& process, uintptr_t address, size_t maxOffset,
                         std::function<bool(uintptr_t, uintptr_t)> callback,
                         std::optional<std::unordered_set<uintptr_t>> cache = std::nullopt, uintptr_t depth = 0);
#endif
