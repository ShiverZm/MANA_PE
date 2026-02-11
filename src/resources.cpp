#include "mana_pe.h"
#include "resources.h"
#include "nt_values.h"
#include "PE_structs.h"
#include <vector>
#include <string>
namespace mana {

bool MANA_PE::_read_image_resource_directory(image_resource_directory& dir,
                                             unsigned int offset) const {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    if (offset) {
        offset = rva_to_offset(_ioh.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE]
                                   .VirtualAddress) +
                 offset;
        if (!offset || fseek(_file_fp, offset, SEEK_SET)) {
            return false;
        }
    }
    unsigned int size = 2 * sizeof(uint32_t) + 4 * sizeof(uint16_t);
    dir.Entries.clear();
    if (size != fread(&dir, 1, size, _file_fp)) {
        return false;
    }
    for (auto i = 0; i < dir.NumberOfIdEntries + dir.NumberOfNamedEntries;
         ++i) {
        image_resource_directory_entry entry;
        size = 2 * sizeof(uint32_t);
        if (size != fread(&entry, 1, size, _file_fp)) {
            return false;
        }
        // For named entries, NameOrId is a RVA to a string:
        // retrieve it and NameOrId has high bit set to 1.
        if (entry.NameOrId & 0x80000000) {
            // The offset of the string is relative
            auto name_offset =
                rva_to_offset(_ioh.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE]
                                  .VirtualAddress) +
                (entry.NameOrId & 0x7FFFFFFF);
            if (!name_offset ||
                !utils::read_string_at_offset(_file_fp, name_offset,
                                              entry.NameStr, true)) {
                return false;
            }
        }
        // Immediately reject obvious bogus entries.
        if ((entry.OffsetToData & 0x7FFFFFFF) > _file_size) {
            continue;
        }
        dir.Entries.push_back(entry);
    }
    return true;
}

std::vector<uint8_t> Resource::get_raw_data() const {
    std::vector<uint8_t> res;
    unsigned int read_bytes;
    // Linux doesn't throw std::bad_alloc,
    // instead it has OOM Killer shutdown the process.
    // This workaround prevents Manalyze from crashing
    // by bounding how much memory can be requested.
#ifdef BOOST_POSIX_API
    struct stat st;
    stat(_path_to_pe.c_str(), &st);
    if (_size > st.st_size) {
        PRINT_ERROR << "Resource " << *get_name()
                    << " is"
                       "// bigger than the PE. Not trying to load it in memory."
                    << DEBUG_INFO << std::endl;
        return res;
    }
#endif
    try {
        res.resize(_size);
    } catch (const std::exception& e) {
        (void)e;
        return res;
    }
    read_bytes = (unsigned int)fread(&res[0], 1, _size, _file_fp);
    // We got less bytes than expected: reduce the vector's size.
    if (read_bytes != _size) {
        res.resize(read_bytes);
    }

    return res;
}

bool parse_version_info_header(vs_version_info_header& header, FILE* f) {
    memset(&header, 0, 3 * sizeof(uint16_t));
    if (3 * sizeof(uint16_t) != fread(&header, 1, 3 * sizeof(uint16_t), f)) {
        return false;
    }
    header.Key = utils::read_unicode_string(f);
    // Next structure is 4-bytes aligned
    unsigned int padding = ftell(f) % 4;
    return !fseek(f, padding, SEEK_CUR);
}

template <>
vs_version_info_t Resource::interpret_as() {
    vs_version_info_t res;

    if (!_offset_in_file || fseek(_file_fp, _offset_in_file, SEEK_SET)) {
        return res;
    }
    if (_type != "RT_VERSION") {
        return res;
    }
    // Is calculated by calling ftell before and
    // after reading a structure, and keeping the difference.
    unsigned int bytes_read;
    unsigned int bytes_remaining;
    unsigned int language;
    std::stringstream ss;
    vs_version_info_header current_structure;
    if (!parse_version_info_header(res.Header, _file_fp)) {
        return res;
    }
    memset(&res.Value, 0, sizeof(fixed_file_info));
    // 0xFEEF04BD is a magic located at the
    // beginning of the VS_FIXED_FILE_INFO structure.
    if (sizeof(fixed_file_info) !=
            fread(&res.Value, 1, sizeof(fixed_file_info), _file_fp) ||
        res.Value.Signature != 0xfeef04bd) {
        return res;
    }
    bytes_read = ftell(_file_fp);
    if (!parse_version_info_header(current_structure, _file_fp)) {
        return res;
    }
    // This (uninteresting) VAR_FILE_INFO structure
    // may be located before the STRING_FILE_INFO we're after.
    // In this case, just skip it.
    if (current_structure.Key == "VarFileInfo") {
        bytes_read = ftell(_file_fp) - bytes_read;
        fseek(_file_fp, current_structure.Length - bytes_read, SEEK_CUR);
        if (!parse_version_info_header(current_structure, _file_fp)) {
            return res;
        }
    }
    if (current_structure.Key != "StringFileInfo") {
        return res;
    }

    // We don't need the contents of StringFileInfo.
    // Replace them with the next structure.
    bytes_read = ftell(_file_fp);
    if (!parse_version_info_header(current_structure, _file_fp)) {
        return res;
    }
    // In the file, the language information
    // is an int stored into a "unicode" string.
    ss << std::hex << current_structure.Key;
    ss >> language;
    if (!ss.fail()) {
        res.Language =
            nt::translate_to_flag((language >> 16) & 0xFFFF, nt::LANG_IDS);
    } else {
        res.Language = "UNKNOWN";
    }
    bytes_read = ftell(_file_fp) - bytes_read;
    if (current_structure.Length < bytes_read) {
        return res;
    }
    bytes_remaining = current_structure.Length - bytes_read;
    while (bytes_remaining > 0) {
        bytes_read = ftell(_file_fp);
        if (!parse_version_info_header(current_structure, _file_fp)) {
            return res;
        }
        std::string value;
        // If the string is null, there won't even be a null terminator.
        if (ftell(_file_fp) - bytes_read < current_structure.Length) {
            value = utils::read_unicode_string(_file_fp);
        }
        bytes_read = ftell(_file_fp) - bytes_read;
        if (bytes_remaining < bytes_read) {
            bytes_remaining = 0;
        } else {
            bytes_remaining -= bytes_read;
        }
        // Add the key/value to our internal representation
        auto p = string_pair(current_structure.Key, value);
        res.StringTable.push_back(p);
        // The next structure is 4byte aligned.
        unsigned int padding = ftell(_file_fp) % 4;
        if (padding) {
            fseek(_file_fp, padding, SEEK_CUR);
            // The last padding doesn't seem to be included
            // in the length given by the structure.
            // So if there are no more remaining bytes,
            // don't stop here. (Otherwise, integer underflow.)
            if (padding < bytes_remaining) {
                bytes_remaining -= padding;
            } else {
                bytes_remaining = 0;
            }
        }
    }
    return res;
}
}  // namespace mana
