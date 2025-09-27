#include "pch.hpp"

static std::fstream CrcLog;

static uint32_t CalculateCrc(const std::string& FileName)
{
    // Reading file

    std::ifstream file(FileName, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.fail())
    {
        std::cerr << "WARNING: failed to open " << FileName << '\n';
        return 0;
    }

    const size_t FileSz = file.tellg();
    char* base = new char[FileSz];

    file.seekg(0, std::ios::beg);
    file.read(base, FileSz);
    file.close();

    // Checking valve signature ("VLV")

    if (strncmp(base + 0x40, "VLV", 3))
    {
        delete[] base;
        return 0;
    }

    // Getting .text

    const auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    const IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(NtHeader);

    bool found = false;

    for (WORD i = 0, const sz = NtHeader->FileHeader.NumberOfSections; i < sz; ++i, ++sh)
    {
        if (!strcmp(reinterpret_cast<const char*>(sh->Name), ".text"))
        {
            found = true;
            break;
        }
    }

    // Calculating CRC hash

    const uint32_t CrcHash = CRC::Calculate(base + sh->PointerToRawData, sh->SizeOfRawData, CRC::CRC_32());

    delete[] base;

    return CrcHash;
}

static void CalculateHashes()
{
    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::current_path()))
    {
        // Checking file extension

        const std::filesystem::path path = entry.path();

        if (strcmp(path.extension().string().c_str(), ".dll"))
            continue;

        // Calculating CRC

        const std::string FileName = path.filename().string();
        const uint32_t CrcHash = CalculateCrc(FileName);

        if (CrcHash)
        {
            std::cout << FileName << " CRC: 0x" << std::hex << std::uppercase << CrcHash << '\n';
            CrcLog << CrcHash << '\n';
        }
    }
}

static void CompareHashes()
{
    std::string line;
    std::vector<uint32_t> ExpectedHashes;

    while (std::getline(CrcLog, line) && !line.empty())
    {
        ExpectedHashes.push_back(static_cast<uint32_t>(std::stoul(line)));
    }

    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::current_path()))
    {
        // Checking file extension

        const std::string filename = entry.path().filename().string();

        if (!filename.ends_with(".dll"))
            continue;

        // Calculating CRC

        const uint32_t CrcHash = CalculateCrc(filename);

        if (CrcHash)
        {
            if (std::find(ExpectedHashes.begin(), ExpectedHashes.end(), CrcHash) != ExpectedHashes.end())
            {
                std::cout << "CRC MATCHED: " << filename << " -> 0x" << std::hex << std::uppercase << CrcHash << '\n';
            }
            else
            {
                std::cout << "UNKNOWN CRC: " << filename << " -> 0x" << std::hex << std::uppercase << CrcHash << '\n';
            }
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc > 1 && !_stricmp(argv[1], "c"))
    {
        CrcLog.open("crc.txt", std::ios::out | std::ios::trunc);

        CalculateHashes();
    }
    else
    {
        CrcLog.open("crc.txt", std::ios::in);

        CompareHashes();
    }

    CrcLog.close();
    return 0;
}