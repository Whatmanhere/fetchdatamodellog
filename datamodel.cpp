// Created By User on 1.20.2025 Using Clion
#include "datamodel.hpp" //sorry for messy code -/whatman/virtualtable
std::optional<std::string> fetchLatestLogFile(const std::string& directoryPath) {
    std::optional<std::string> newestFile;
    std::filesystem::file_time_type mostRecentTime;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
            if (entry.is_regular_file() && entry.path().extension() == ".log") { // log method revived
                auto fileTime = std::filesystem::last_write_time(entry);

                if (!newestFile || fileTime > mostRecentTime) {
                    newestFile = entry.path().string();
                    mostRecentTime = fileTime;
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) { //filesys
        std::cerr << "Filesystem error encountered: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "General error encountered: " << e.what() << std::endl;
        return std::nullopt;
    }
    return newestFile;
}
std::string loadFileContent(const std::string& pathToFile) { //loadcnt
    std::ifstream file(pathToFile);
    if (!file) {
        std::cerr << "Failed to open file: " << pathToFile << std::endl;
        return "";
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
uintptr_t extractThreadId(const std::string& fileContent) { //threadid
    std::regex logPattern(R"(::fetchDataModel: \(stage:\d+, window = 0x[a-zA-Z\d]+\) \[tid:(0x[a-zA-Z\d]+)\])");
    std::smatch matches;
    std::string::const_iterator searchBegin(fileContent.cbegin());
    uintptr_t threadId = 0;
    while (std::regex_search(searchBegin, fileContent.cend(), matches, logPattern)) {
        std::cout << "Match found in logs: " << matches[0] << std::endl;
        threadId = std::stoull(matches[1], nullptr, 16);
        searchBegin = matches.suffix().first;
    }
    return threadId;
}
std::string decodeSymbol(const std::string& mangledName) { //decode
    std::string decodedName(1024, '\0');
    std::string inputName = mangledName;
    if (inputName.starts_with(".?AV")) {
        inputName = "?" + inputName.substr(4);
    }
    DWORD length = UnDecorateSymbolName(inputName.c_str(), decodedName.data(), decodedName.capacity(), UNDNAME_COMPLETE); 
    if (!length) {
        return inputName;
    }
    decodedName.resize(length);
    if (decodedName.starts_with(" ??")) {
        decodedName = decodedName.substr(4);
    }
    return decodedName;
}
uintptr_t findModuleAddress(std::unique_ptr<process_t>& activeProcess, uintptr_t address) {
    for (auto& module : activeProcess->module_factory.modules()) {
        if (module->contains(address)) {
            return module->address();
        }
    }
    return 0;
}
bool verifyAddress(std::unique_ptr<process_t>& activeProcess, uintptr_t address) {
    auto testBuffer = activeProcess->memory_factory.read(address, 0x1);
    return testBuffer != nullptr;
}
std::optional<std::string> retrieveRTTIName(std::unique_ptr<process_t>& activeProcess, uintptr_t objAddress) {
    uintptr_t vtableAddr = activeProcess->memory_factory.read<uintptr_t>(objAddress);
    if (!vtableAddr) {
        return std::nullopt;
    }
    if (!verifyAddress(activeProcess, vtableAddr - sizeof(uintptr_t))) {
        return std::nullopt;
    }
    uintptr_t locatorAddr = activeProcess->memory_factory.read<uintptr_t>(vtableAddr - sizeof(uintptr_t));
    if (!locatorAddr) {
        return std::nullopt;
    }
    if (!verifyAddress(activeProcess, locatorAddr)) {
        return std::nullopt;
    }
    CompleteObjectLocator locator = activeProcess->memory_factory.read<CompleteObjectLocator>(locatorAddr);
    uintptr_t typeInfoAddr = locator.typeInfoAddr + findModuleAddress(activeProcess, locatorAddr);
    if (!verifyAddress(activeProcess, typeInfoAddr)) {
        return std::nullopt;
    }
    TypeInformation typeInfo = activeProcess->memory_factory.read<TypeInformation>(typeInfoAddr);
    return decodeSymbol(typeInfo.name);
}
void disableMemoryPoolMonitor(std::unique_ptr<process_t>& activeProcess) {
    std::optional<std::uintptr_t> monitoredPool;
    do {
        for (const auto& memoryRegion : activeProcess->memory_factory.regions()) {
            if (memoryRegion.type() != memory::region_t::type_t::private_t || memoryRegion.state() != memory::region_t::state_t::commit_t) {
                continue;
            }
            if (memoryRegion.protection() == memory::protection_flags_t::readwrite && memoryRegion.size() == 0x200000) {
                std::cout << "[info] Located monitored memory pool at 0x" << std::hex << memoryRegion.address()
                          << ", size: " << memoryRegion.size() << " bytes" << std::endl;
                monitoredPool = memoryRegion.address();
                break;
            }
        }
        if (!monitoredPool) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } while (!monitoredPool);

    activeProcess->memory_factory.write<std::uintptr_t>(*monitoredPool + 0x208, 0x20);
}

void recursiveTraversal(std::unique_ptr<process_t>& activeProcess, uintptr_t baseAddr, size_t maxOffset,
                        std::function<bool(uintptr_t, uintptr_t)> callback, 
                        std::optional<std::unordered_set<uintptr_t>> cacheOpt, uintptr_t depth = 0) {
    std::unordered_set<uintptr_t> visited = cacheOpt.value_or(std::unordered_set<uintptr_t>());

    if (visited.contains(baseAddr)) {
        return;
    }

    for (size_t offset = 0; offset < maxOffset; offset += 8) {
        if (!verifyAddress(activeProcess, baseAddr + offset)) {
            continue;
        }

        uintptr_t targetAddr = activeProcess->memory_factory.read<uintptr_t>(baseAddr + offset);

        if (!verifyAddress(activeProcess, targetAddr)) {
            continue;
        }
        std::cout << "[debug] Visiting address: 0x" << std::hex << targetAddr << " at depth " << depth << std::endl;

        if (!callback(targetAddr, depth)) {
            return;
        }
        recursiveTraversal(activeProcess, targetAddr, 0x200, callback, visited, depth + 1);
        visited.emplace(targetAddr);
    }
}
uintptr_t locateDataModelPointer(std::unique_ptr<process_t>& activeProcess, uintptr_t threadId) {
    uintptr_t dataModelAddr = 0;

    recursiveTraversal(activeProcess, threadId, 22160, [&](uintptr_t addr, uintptr_t depth) -> bool {
        if (dataModelAddr) {
            return false;
        }
        auto rtti = retrieveRTTIName(activeProcess, addr);
        if (rtti.has_value()) {
            const std::string& name = rtti.value();
            //REAL LMAO
            if (name == "RBX::Script" || name == "RBX::ScriptContainer" || name == "RBX::Workspace") {
                uintptr_t ancestor = getFirstAncestor(activeProcess, addr);
                auto ancestorRTTI = retrieveRTTIName(activeProcess, ancestor);
                if (ancestorRTTI.has_value() && ancestorRTTI.value() == "RBX::RootDataModel") {
                    dataModelAddr = ancestor;
                    return false;
                }
            }
        }
        return (depth <= 5);
    }, std::nullopt);

    if (!dataModelAddr) {
        return locateDataModelPointer(activeProcess, threadId);
    }
    return dataModelAddr;
}
    // roblox heh, sigma
int main() {
    std::unique_ptr<process_t> activeProcess = nullptr;
    do {
        activeProcess = process_t::open("RobloxPlayerBeta.exe");

        if (!activeProcess) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } while (!activeProcess);

    std::optional<std::string> logFile = fetchLatestLogFile(logPath);
    if (!logFile.has_value()) {
        std::cerr << "Couldn't find the latest log file." << std::endl;
        return 1;
    }
    uint64_t threadId = extractThreadId(loadFileContent(logFile.value()));
    if (!threadId) {
        std::cerr << "Couldn't extract thread ID." << std::endl; //rel
        return 1;
    }
    //mempoolmon
    disableMemoryPoolMonitor(activeProcess);
    //ok so this why i was crashing
    uintptr_t dataModelPointer = locateDataModelPointer(activeProcess, threadId);
    std::cout << "DataModel Pointer: 0x" << std::hex << dataModelPointer << std::endl;
    return 0;
}