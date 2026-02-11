#ifndef SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_NT_VALUES_H_
#define SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_NT_VALUES_H_

#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <stdint.h>
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0           // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1           // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2         // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3        // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4         // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5        // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6            // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7        // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7     // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8        // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS 9              // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10     // Load Configuration Dir
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11    // Bound Import Dir headers
#define IMAGE_DIRECTORY_ENTRY_IAT 12             // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13    // Delay Load Import Des
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14  // COM Runtime descriptor

#ifndef WIN_CERT_TYPE_PKCS_SIGNED_DATA
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 2
#endif
namespace nt {
typedef std::map<std::string, int> flag_dict;

std::vector<std::string> translate_to_flags(int value, const flag_dict& dict);
extern flag_dict IMAGE_OPTIONAL_HEADER_MAGIC;
extern flag_dict MACHINE_TYPES;
extern const flag_dict RESOURCE_TYPES;
extern const flag_dict LANG_IDS;
extern const flag_dict DEBUG_TYPES;
extern const flag_dict GLOBAL_FLAGS;
extern const flag_dict WIN_CERTIFICATE_TYPES;
extern const flag_dict WIN_CERTIFICATE_REVISIONS;
extern const flag_dict PE_CHARACTERISTICS;
extern const flag_dict SUBSYSTEMS;
extern const flag_dict DLL_CHARACTERISTICS;
extern const flag_dict SECTION_CHARACTERISTICS;
extern const flag_dict CODEPAGES;
extern const flag_dict FIXEDFILEINFO_FILEFLAGS;
extern const flag_dict FIXEDFILEINFO_FILEOS;
extern const flag_dict FIXEDFILEINFO_FILETYPE;
extern const flag_dict FIXEDFILEINFO_FILESUBTYPE_DRV;
extern const flag_dict FIXEDFILEINFO_FILESUBTYPE_FONT;

std::string translate_to_flag(int value, const flag_dict& dict);
std::string timestamp_to_string(uint32_t timestamp);
}  // namespace nt

#endif  // SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_NT_VALUES_H_
