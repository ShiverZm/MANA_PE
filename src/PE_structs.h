#ifndef SRC_PE_ATTRIBUTES_INCLUDE_PE_STRUCTS_H_
#define SRC_PE_ATTRIBUTES_INCLUDE_PE_STRUCTS_H_
#include <vector>
#include <string>
#include <stdint.h>

namespace mana {

typedef struct dos_header_t {
    uint8_t e_magic[2] = {0};
    uint16_t e_cblp = 0;
    uint16_t e_cp = 0;
    uint16_t e_crlc = 0;
    uint16_t e_cparhdr = 0;
    uint16_t e_minalloc = 0;
    uint16_t e_maxalloc = 0;
    uint16_t e_ss = 0;
    uint16_t e_sp = 0;
    uint16_t e_csum = 0;
    uint16_t e_ip = 0;
    uint16_t e_cs = 0;
    uint16_t e_lfarlc = 0;
    uint16_t e_ovno = 0;
    uint16_t e_res[4] = {0};
    uint16_t e_oemid = 0;
    uint16_t e_oeminfo = 0;
    uint16_t e_res2[10] = {0};
    uint32_t e_lfanew = 0;
} dos_header;

typedef struct dos_header_str_t {
    char e_magic[16] = {0};
    char e_cblp[16] = {0};
    char e_cp[16] = {0};
    char e_crlc[16] = {0};
    char e_cparhdr[16] = {0};
    char e_minalloc[16] = {0};
    char e_maxalloc[16] = {0};
    char e_ss[16] = {0};
    char e_sp[16] = {0};
    char e_csum[16] = {0};
    char e_ip[16] = {0};
    char e_cs[16] = {0};
    char e_lfarlc[16] = {0};
    char e_ovno[16] = {0};
    char e_res[16] = {0};
    char e_oemid[16] = {0};
    char e_oeminfo[16] = {0};
    char e_res2[16] = {0};
    char e_lfanew[16] = {0};
} dos_header_str;

typedef struct pe_header_t {
    uint8_t Signature[4] = {0};
    uint16_t Machine = 0;
    uint16_t NumberofSections = 0;
    uint32_t TimeDateStamp = 0;
    uint32_t PointerToSymbolTable = 0;
    uint32_t NumberOfSymbols = 0;
    uint16_t SizeOfOptionalHeader = 0;
    uint16_t Characteristics = 0;
} pe_header;

typedef struct pe_header_str_t {
    char Signature[4] = {0};
    char Machine[32] = {0};
    uint16_t NumberofSections = 0;
    char TimeDateStamp[32] = {0};
    char PointerToSymbolTable[32] = {0};
    uint32_t NumberOfSymbols = 0;
    char SizeOfOptionalHeader[32] = {0};
    char Characteristics[32] = {0};
} pe_header_str;

typedef struct image_data_directory_t {
    uint32_t VirtualAddress = 0;
    uint32_t Size = 0;
} image_data_directory;

typedef struct image_optional_header_t {
    uint16_t Magic = 0;
    uint8_t MajorLinkerVersion = 0;
    uint8_t MinorLinkerVersion = 0;
    uint32_t SizeOfCode = 0;
    uint32_t SizeOfInitializedData = 0;
    uint32_t SizeOfUninitializedData = 0;
    uint32_t AddressOfEntryPoint = 0;
    uint32_t BaseOfCode = 0;
    uint32_t BaseOfData = 0;
    uint64_t ImageBase = 0;
    uint32_t SectionAlignment = 0;
    uint32_t FileAlignment = 0;
    uint16_t MajorOperatingSystemVersion = 0;
    uint16_t MinorOperatingSystemVersion = 0;
    uint16_t MajorImageVersion = 0;
    uint16_t MinorImageVersion = 0;
    uint16_t MajorSubsystemVersion = 0;
    uint16_t MinorSubsystemVersion = 0;
    uint32_t Win32VersionValue = 0;
    uint32_t SizeOfImage = 0;
    uint32_t SizeOfHeaders = 0;
    uint32_t Checksum = 0;
    uint16_t Subsystem = 0;
    uint16_t DllCharacteristics = 0;
    uint64_t SizeofStackReserve = 0;
    uint64_t SizeofStackCommit = 0;
    uint64_t SizeofHeapReserve = 0;
    uint64_t SizeofHeapCommit = 0;
    uint32_t LoaderFlags = 0;
    uint32_t NumberOfRvaAndSizes = 0;
    image_data_directory directories[0x10] = {0};
} image_optional_header;

typedef struct image_section_header_t {
    uint8_t Name[8] = {0};
    uint32_t VirtualSize = 0;
    uint32_t VirtualAddress = 0;
    uint32_t SizeOfRawData = 0;
    uint32_t PointerToRawData = 0;
    uint32_t PointerToRelocations = 0;
    uint32_t PointerToLineNumbers = 0;
    uint16_t NumberOfRelocations = 0;
    uint16_t NumberOfLineNumbers = 0;
    uint32_t Characteristics = 0;
} image_section_header;

typedef struct coff_symbol_t {
    uint8_t Name[8] = {0};
    uint32_t Value = 0;
    uint16_t SectionNumber = 0;
    uint16_t Type = 0;
    uint8_t StorageClass = 0;
    uint8_t NumberOfAuxSymbols = 0;
} coff_symbol;

typedef struct import_lookup_table_t {
    uint64_t AddressOfData = 0;
    uint16_t Hint = 0;
    std::string Name;
} import_lookup_table;

typedef struct image_import_descriptor_t {
    uint32_t OriginalFirstThunk = 0;
    uint32_t TimeDateStamp = 0;
    uint32_t ForwarderChain = 0;
    uint32_t Name = 0;
    uint32_t FirstThunk = 0;

    std::string import_Name;
    std::vector<import_lookup_table> import_lookup;
} image_import_descriptor;

typedef struct delay_load_directory_table_t {
    uint32_t Attributes = 0;
    uint32_t Name = 0;
    uint32_t ModuleHandle = 0;
    uint32_t DelayImportAddressTable = 0;
    uint32_t DelayImportNameTable = 0;
    uint32_t BoundDelayImportTable = 0;
    uint32_t UnloadDelayImportTable = 0;
    uint32_t TimeStamp = 0;
    std::string NameStr;
} delay_load_directory_table;

typedef struct exported_function_t {
    uint32_t Ordinal = 0;
    uint32_t Address = 0;
    std::string Name;
    std::string ForwardName;
} exported_function;

typedef struct image_export_directory_t {
    uint32_t Characteristics = 0;
    uint32_t TimeDateStamp = 0;
    uint16_t MajorVersion = 0;
    uint16_t MinorVersion = 0;
    uint32_t Name = 0;
    uint32_t Base = 0;
    uint32_t NumberOfFunctions = 0;
    uint32_t NumberOfNames = 0;
    uint32_t AddressOfFunctions = 0;
    uint32_t AddressOfNames = 0;
    uint32_t AddressOfNameOrdinals = 0;
    std::string NameStr;
} image_export_directory;

typedef struct image_resource_data_entry_t {
    uint32_t OffsetToData = 0;
    uint32_t Size = 0;
    uint32_t Codepage = 0;
    uint32_t Reserved = 0;
} image_resource_data_entry;

typedef struct image_resource_directory_entry_t {
    uint32_t NameOrId = 0;
    uint32_t OffsetToData = 0;
    std::string NameStr;
} image_resource_directory_entry;

typedef struct image_resource_directory_t {
    uint32_t Characteristics = 0;
    uint32_t TimeDateStamp = 0;
    uint16_t MajorVersion = 0;
    uint16_t minorVersion = 0;
    uint16_t NumberOfNamedEntries = 0;
    uint16_t NumberOfIdEntries = 0;
    std::vector<image_resource_directory_entry> Entries;
} image_resource_directory;

typedef struct debug_directory_entry_t {
    uint32_t Characteristics = 0;
    uint32_t TimeDateStamp = 0;
    uint16_t MajorVersion = 0;
    uint16_t MinorVersion = 0;
    uint32_t Type = 0;
    uint32_t SizeofData = 0;
    uint32_t AddressOfRawData = 0;
    uint32_t PointerToRawData = 0;
    // Non-standard!
    std::string Filename;
} debug_directory_entry;

typedef struct pdb_info_t {
    uint32_t Signature = 0;
    uint8_t Guid[16] = {0};
    uint32_t Age = 0;
    std::string PdbFileName;
} pdb_info;

typedef struct image_debug_misc_t {
    uint32_t DataType = 0;
    uint32_t Length = 0;
    uint8_t Unicode = 0;
    uint8_t Reserved[3] = {0};
    std::string DbgFile;
} image_debug_misc;

typedef struct image_base_relocation_t {
    uint32_t PageRVA = 0;
    uint32_t BlockSize = 0;
    // Non-standard!
    std::vector<uint16_t> TypesOffsets;
} image_base_relocation;

typedef struct image_tls_directory_t {
    uint64_t StartAddressOfRawData = 0;
    uint64_t EndAddressOfRawData = 0;
    uint64_t AddressOfIndex = 0;
    uint64_t AddressOfCallbacks = 0;
    uint32_t SizeOfZeroFill = 0;
    uint32_t Characteristics = 0;
    // Non-standard!
    std::vector<uint64_t> Callbacks;

    void clear() {
        StartAddressOfRawData = 0;
        EndAddressOfRawData = 0;
        AddressOfIndex = 0;
        AddressOfCallbacks = 0;
        SizeOfZeroFill = 0;
        Callbacks.clear();
        Callbacks.shrink_to_fit();
    }
} image_tls_directory;

typedef struct image_load_config_code_integrity_t {
    uint16_t Flags = 0;
    uint16_t Catalog = 0;
    uint32_t CatalogOffset = 0;
    uint32_t Reserved = 0;
} image_load_config_code_integrity;

// ---------------------------------------------------

typedef struct image_load_config_directory_t {
    uint32_t Size = 0;
    uint32_t TimeDateStamp = 0;
    uint16_t MajorVersion = 0;
    uint16_t MinorVersion = 0;
    uint32_t GlobalFlagsClear = 0;
    uint32_t GlobalFlagsSet = 0;
    uint32_t CriticalSectionDefaultTimeout = 0;
    uint64_t DeCommitFreeBlockThreshold = 0;
    uint64_t DeCommitTotalFreeThreshold = 0;
    uint64_t LockPrefixTable = 0;
    uint64_t MaximumAllocationSize = 0;
    uint64_t VirtualMemoryThreshold = 0;
    uint64_t ProcessAffinityMask = 0;
    uint32_t ProcessHeapFlags = 0;
    uint16_t CSDVersion = 0;
    uint16_t Reserved1 = 0;
    uint64_t EditList = 0;
    uint64_t SecurityCookie = 0;
    uint64_t SEHandlerTable = 0;
    uint64_t SEHandlerCount = 0;
    uint64_t GuardCFCheckFunctionPointer = 0;
    uint64_t GuardCFDispatchFunctionPointer = 0;
    uint64_t GuardCFFunctionTable = 0;
    uint64_t GuardCFFunctionCount = 0;
    uint32_t GuardFlags = 0;
    image_load_config_code_integrity CodeIntegrity;
    uint64_t GuardAddressTakenIatEntryTable = 0;
    uint64_t GuardAddressTakenIatEntryCount = 0;
    uint64_t GuardLongJumpTargetTable = 0;
    uint64_t GuardLongJumpTargetCount = 0;
} image_load_config_directory;

typedef struct win_certificate_t {
    uint32_t Length = 0;
    uint16_t Revision = 0;
    uint16_t CertificateType = 0;
    std::vector<uint8_t> Certificate;
} win_certificate;

typedef struct vs_version_info_header_t {
    uint16_t Length = 0;
    uint16_t ValueLength = 0;
    uint16_t Type = 0;
    std::string Key;
} vs_version_info_header;

typedef struct vs_fixed_file_info_t {
    uint32_t Signature = 0;
    uint32_t StructVersion = 0;
    uint32_t FileVersionMS = 0;
    uint32_t FileVersionLS = 0;
    uint32_t ProductVersionMS = 0;
    uint32_t ProductVersionLS = 0;
    uint32_t FileFlagsMask = 0;
    uint32_t FileFlags = 0;
    uint32_t FileOs = 0;
    uint32_t FileType = 0;
    uint32_t FileSubtype = 0;
    uint32_t FileDateMS = 0;
    uint32_t FileDateLS = 0;
} fixed_file_info;

typedef std::pair<std::string, std::string> string_pair;

typedef struct vs_version_info_t {
    vs_version_info_header Header;
    fixed_file_info Value;
    std::string Language;
    std::vector<string_pair> StringTable;
} version_info;
}  // namespace mana

#endif  // SRC_PE_ATTRIBUTES_INCLUDE_PE_STRUCTS_H_
