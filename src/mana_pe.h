#ifndef SRC_PE_ATTRIBUTES_INCLUDE_PE_MANA_PE_H_
#define SRC_PE_ATTRIBUTES_INCLUDE_PE_MANA_PE_H_

#pragma once

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <string>
#include <vector>
#include <set>
#include <exception>

#include "PE_structs.h"
#include "resources.h"

#define MANA_PE_PARSE_NONE 0x0000
#define MANA_PE_PARSE_DOS_HEADER 0x0001
#define MANA_PE_PARSE_PE_HEADER 0x0002
#define MANA_PE_PARSE_IO_HEADER 0x0004
#define MANA_PE_PARSE_SECTION_TABLE 0x0008
#define MANA_PE_PARSE_COFF_SYSBOLS 0x0010

#define MANA_PE_PARSE_IMPORTS 0x0020
#define MANA_PE_PARSE_DELAYED_IMPORTS 0x0040
#define MANA_PE_PARSE_EXPORTS 0x0080
#define MANA_PE_PARSE_RESOURCES 0x0100
#define MANA_PE_PARSE_DEBUG 0x0200
#define MANA_PE_PARSE_RELOCATIONS 0x0400
#define MANA_PE_PARSE_TLS 0x0800
#define MANA_PE_PARSE_CONFIG 0x1000
#define MANA_PE_PARSE_CERTIFICATES 0x2000

#define MANA_PE_PARSE_ALL 0xFFFF

namespace mana {
class MANA_PE {
 public:
    MANA_PE()
        : _initialized(false),
          _file_fp(nullptr),
          _h_dos_flag(false),
          _h_pe_flag(false),
          _ioh_flag(false){};

    explicit MANA_PE(const std::wstring& path,
                     uint32_t parse_flag = MANA_PE_PARSE_ALL);

    virtual ~MANA_PE() {
        if (_file_fp != nullptr) {
            fclose(_file_fp);
            _file_fp = nullptr;
        }
    }

    uint64_t get_filesize() const;

    const dos_header& get_dos_header() const { return _h_dos; }

    const pe_header& get_pe_header() const { return _h_pe; }

    const std::vector<image_import_descriptor>& get_imports() const {
        return _imports;
    }

    const image_optional_header& get_image_optional_header() const {
        return _ioh;
    }

    enum PE_ARCHITECTURE { x86, x64 };

    PE_ARCHITECTURE get_architecture() const;

    const std::vector<image_section_header>& get_sections() const {
        return _sections;
    }

    const delay_load_directory_table& get_delay_load_table() const {
        return _delay_load_directory_table;
    }

    const std::vector<exported_function>& get_exports() const {
        return _exports;
    }

    const std::vector<Resource>& get_resources() const { return _resources; }

    const std::vector<debug_directory_entry>& get_debug() const {
        return _debug_entries;
    }

    const image_tls_directory& get_tls() const { return _tls; }

    const image_load_config_directory& get_config() const { return _config; }

    const std::string& get_err_string() const { return _err_string; }

    FILE* get_obj_file_fp() const { return _file_fp; }

    bool get_result_code() const { return _initialized; }
    bool find_section(unsigned int rva, image_section_header& res);
    static bool is_address_in_section(
        uint64_t rva, const image_section_header& section,
        bool check_raw_size = false);

 protected:
    /**
     * Reads the first bytes of the file to reconstruct the DOS header.
     */
    bool _parse_dos_header();
    bool _parse_pe_header();
    bool _parse_image_optional_header();
    bool _parse_section_table();
    bool _parse_coff_symbols();
    bool _parse_directories();
    bool _parse_imports();
    bool _parse_delayed_imports();
    bool _reach_directory(int directory) const;
    unsigned int rva_to_offset(uint64_t rva) const;
    bool _parse_import_lookup_table(unsigned int offset,
                                    image_import_descriptor* library);
    bool _parse_hint_name_table(import_lookup_table* import);
    bool _parse_exports();
    bool _parse_resources();
    bool _parse_debug();
    bool _parse_relocations();
    bool _parse_tls();
    bool _parse_config();
    bool _parse_certificates();
    bool _read_image_resource_directory(image_resource_directory& dir,
                                        unsigned int offset = 0) const;
    unsigned int _va_to_offset(uint64_t va) const;

    std::wstring _path;
    bool _initialized = false;
    uint64_t _file_size = 0;
    FILE* _file_fp = nullptr;
    /*
    -----------------------------------
    Fields related to the PE structure.
    -----------------------------------
    Those fields that are extremely close to the PE format and offer little
    abstraction.

     */
    std::string _err_string;
    dos_header _h_dos;
    bool _h_dos_flag = false;
    pe_header _h_pe;
    bool _h_pe_flag = false;
    image_optional_header _ioh;
    bool _ioh_flag = false;
    uint32_t _parse_flag = 0;
    std::vector<image_section_header> _sections;
    std::vector<coff_symbol> _coff_symbols;
    std::vector<std::string> _coff_string_table;
    std::vector<image_import_descriptor> _imports;
    delay_load_directory_table _delay_load_directory_table;
    std::vector<exported_function> _exports;
    image_export_directory _ied;
    std::vector<Resource> _resources;
    std::vector<debug_directory_entry> _debug_entries;
    std::vector<image_base_relocation> _relocations;
    image_tls_directory _tls;
    image_load_config_directory _config;
    std::vector<win_certificate> _certificates;
};

class MANA_PE_EXT : public MANA_PE {
 public:
    MANA_PE_EXT() {}
    ~MANA_PE_EXT() override {
        if (_file_fp != nullptr) {
            fclose(_file_fp);
            _file_fp = nullptr;
        }
    }

    bool parse_pe(const std::wstring& path,
                  uint32_t parse_flag = MANA_PE_PARSE_ALL);
};
}  // namespace mana
#endif  // SRC_PE_ATTRIBUTES_INCLUDE_PE_MANA_PE_H_
