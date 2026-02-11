//#include "common/Utils.h"
#include "mana_pe.h"
#include "nt_values.h"
#include "utils.h"
#include "resources.h"
#include <algorithm>
#include <string>
namespace mana {
MANA_PE::MANA_PE(const std::wstring& path, uint32_t parse_flag)
    : _path(path),
      _initialized(false),
      _file_fp(nullptr),
      _h_dos_flag(false),
      _h_pe_flag(false),
      _ioh_flag(false),
      _parse_flag(parse_flag) {
    if (parse_flag == MANA_PE_PARSE_NONE) {
        return;
    }

    FILE* f = _wfsopen(_path.c_str(), L"rb", _SH_DENYNO);
    if (f == nullptr) {
        _err_string = "open the file failed";
        return;
    }
    _file_fp = f;
    fseek(f, 0, SEEK_END);
    _file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (_parse_flag & MANA_PE_PARSE_DOS_HEADER) {
        _h_dos_flag = _parse_dos_header();
        if (!_h_dos_flag) {
            return;
        }
    }

    if (_parse_flag & MANA_PE_PARSE_PE_HEADER) {
        _h_pe_flag = _parse_pe_header();
        if (!_h_pe_flag) {
            return;
        }
    }

    if (_parse_flag & MANA_PE_PARSE_IO_HEADER) {
        _ioh_flag = _parse_image_optional_header();
        if (!_ioh_flag) {
            return;
        }
    }

    if (_parse_flag & MANA_PE_PARSE_IO_HEADER) {
        if (!_parse_section_table()) {
            return;
        }
    }

    _initialized = true;

    if (_parse_flag & MANA_PE_PARSE_COFF_SYSBOLS) {
        _parse_coff_symbols();
    }

    _parse_directories();
}

uint64_t MANA_PE::get_filesize() const { return _file_size; }

MANA_PE::PE_ARCHITECTURE MANA_PE::get_architecture() const {
    return (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32+"]
                ? MANA_PE::x64
                : MANA_PE::x86);
}

bool MANA_PE::_parse_directories() {
    if (_file_fp == nullptr) {
        return false;
    }

    bool is_success = false;

    do {
        if (_parse_flag & MANA_PE_PARSE_IMPORTS) {
            if (!_parse_imports()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_DELAYED_IMPORTS) {
            if (!_parse_delayed_imports()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_EXPORTS) {
            if (!_parse_exports()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_RESOURCES) {
            if (!_parse_resources()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_DEBUG) {
            if (!_parse_debug()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_RELOCATIONS) {
            if (!_parse_relocations()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_TLS) {
            if (!_parse_tls()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_CONFIG) {
            if (!_parse_config()) {
                break;
            }
        }

        if (_parse_flag & MANA_PE_PARSE_CERTIFICATES) {
            if (!_parse_certificates()) {
                break;
            }
        }

        is_success = true;
    } while (false);

    return is_success;
}

unsigned int MANA_PE::rva_to_offset(uint64_t rva) const {
    if (!_ioh_flag) {
        return 0;
    }
    // Special case: PE with no sections
    if (_sections.size() == 0) {
        // If the file is bigger than 4Go, this assumption may not be true.
        return rva & 0xFFFFFFFF;
    }
    image_section_header section;
    bool section_find = false;
    memset(&section, 0, sizeof(section));
    auto it1 = std::find_if(
        _sections.begin(), _sections.end(), [rva](const auto& sec) {
            return sec.VirtualAddress <= rva &&
                   rva < sec.VirtualAddress + sec.VirtualSize;
        });
    if (it1 != _sections.end()) {
        section = *it1;
        section_find = true;
    }

    if (!section_find) {
        auto it2 = std::find_if(
            _sections.begin(), _sections.end(), [rva](const auto& sec) {
                return sec.VirtualAddress <= rva &&
                       rva < sec.VirtualAddress + sec.SizeOfRawData;
            });
        if (it2 != _sections.end()) {
            section = *it2;
            section_find = true;
        }
    }

    if (!section_find) {
        return 0;
    }
    // The sections have to be aligned on FileAlignment bytes.
    if (section.PointerToRawData % _ioh.FileAlignment != 0) {
        int new_raw_pointer = (section.PointerToRawData / _ioh.FileAlignment) *
                              _ioh.FileAlignment;
        return (rva - section.VirtualAddress + new_raw_pointer) & 0xFFFFFFFF;
    }

    // Assume that the offset in the
    // file can be stored inside an unsigned integer.
    // PEs whose size is bigger than 4 Go may not be parsed properly.
    return (rva - section.VirtualAddress + section.PointerToRawData) &
           0xFFFFFFFF;
}

unsigned int MANA_PE::_va_to_offset(uint64_t va) const {
    if (!_ioh_flag) {
        // Image Optional Header was not parsed.
        return 0;
    }
    return va > _ioh.ImageBase ? rva_to_offset(va - _ioh.ImageBase) : 0;
}

bool MANA_PE::_reach_directory(int directory) const {
    if (_file_fp == nullptr) {
        return false;
    }
    // There can be no more than 16 directories.
    if (directory >= 0x10) {
        return false;
    }
    if (!_ioh_flag) {
        // Image Optional Header was not parsed.
        return 0;
    }

    if (_ioh.directories[directory].VirtualAddress == 0 &&
        _ioh.directories[directory].Size == 0) {
        // Requested directory is empty.
        return false;
    } else if (_ioh.directories[directory].Size == 0) {
        // Weird, but continue anyway.
    } else if (_ioh.directories[directory].VirtualAddress == 0) {
        return false;
    }
    unsigned int offset =
        rva_to_offset(_ioh.directories[directory].VirtualAddress);

    if (!offset || fseek(_file_fp, offset, SEEK_SET)) {
        return false;
    }
    return true;
}

bool MANA_PE::_parse_certificates() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    // In this case, "VirtualAddress" is actually a file offset.
    if (!_ioh.directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress ||
        fseek(_file_fp,
              _ioh.directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress,
              SEEK_SET)) {
        // Unsigned binary
        return true;
    }

    unsigned int remaining_bytes =
        _ioh.directories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    unsigned int header_size = sizeof(uint32_t) + 2 * sizeof(uint16_t);
    while (remaining_bytes > header_size) {
        win_certificate cert;
        if (header_size != fread(&cert, 1, header_size, _file_fp)) {
            // Recoverable error.
            return true;
        }
        // The certificate may point to garbage. Although other
        // values than the ones defined in nt_values.h
        // are allowed by the PE specification (but which ones?),
        // this is a good heuristic to determine
        // whether we have landed in random bytes.
        if (nt::translate_to_flag(cert.CertificateType,
                                  nt::WIN_CERTIFICATE_TYPES) == "UNKNOWN" &&
            nt::translate_to_flag(cert.Revision,
                                  nt::WIN_CERTIFICATE_REVISIONS) == "UNKNOWN") {
            // Recoverable error.
            return true;
        } else if (cert.CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
            // Get the certificate data anyway.
        }
        try {
            cert.Certificate.resize(cert.Length);
        } catch (const std::exception& e) {
            (void)e;
            return false;
        }
        if (cert.Length < remaining_bytes ||
            cert.Length - header_size != fread(&(cert.Certificate[0]), 1,
                                               cert.Length - header_size,
                                               _file_fp)) {
            return false;
        }
        remaining_bytes -= cert.Length;
        _certificates.push_back(cert);

        // The certificates start on 8-byte aligned addresses
        unsigned int padding = cert.Length % 8;
        if (padding && remaining_bytes) {
            fseek(_file_fp, padding, SEEK_CUR);
            remaining_bytes -= padding;
        }
    }
    return true;
}

bool MANA_PE::_parse_tls() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }

    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_TLS)) {
        // No TLS callbacks
        return true;
    }

    unsigned int size = 4 * sizeof(uint64_t) + 2 * sizeof(uint32_t);
    _tls.clear();

    if (get_architecture() == x64) {
        fread(&_tls, 1, size, _file_fp);
    } else {
        fread(&_tls.StartAddressOfRawData, 1, sizeof(uint32_t), _file_fp);
        fread(&_tls.EndAddressOfRawData, 1, sizeof(uint32_t), _file_fp);
        fread(&_tls.AddressOfIndex, 1, sizeof(uint32_t), _file_fp);
        fread(&_tls.AddressOfCallbacks, 1, sizeof(uint32_t), _file_fp);
        fread(&_tls.SizeOfZeroFill, 1, 2 * sizeof(uint32_t), _file_fp);
    }
    if (feof(_file_fp) || ferror(_file_fp)) {
        _err_string = "Could not read the IMAGE_TLS_DIRECTORY.";
        return false;
    }
    // Go to the offset table
    unsigned int offset = _va_to_offset(_tls.AddressOfCallbacks);
    if (!offset || fseek(_file_fp, offset, SEEK_SET)) {
        _err_string = "Could not reach the TLS callback table.";
        return false;
    }
    uint64_t callback_address = 0;
    unsigned int callback_size =
        _ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+")
            ? sizeof(uint64_t)
            : sizeof(uint32_t);
    // break on null callback
    while (true) {
        if (callback_size !=
                fread(&callback_address, 1, callback_size, _file_fp) ||
            !callback_address) {
            // Exit condition.
            break;
        }
        _tls.Callbacks.push_back(callback_address);
    }

    return true;
}

bool read_config_field(const image_load_config_directory& config, FILE* source,
                       void* destination, unsigned int field_size,
                       unsigned int& read_bytes) {
    if (read_bytes + field_size > config.Size) {
        return false;
    }
    if (1 != fread(destination, field_size, 1, source)) {
        return false;
    }
    read_bytes += field_size;
    return true;
}

bool MANA_PE::_parse_config() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }

    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)) {
        // No TLS callbacks
        return true;
    }
    memset(&_config, 0, sizeof(_config));
    if (24 != fread(&_config, 1, 24, _file_fp)) {
        // Non fatal
        return true;
    }

    // The next few fields are uint32s or
    // uint64s depending on the architecture.
    unsigned int field_size =
        (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32")) ? 4 : 8;
    if (1 != fread(&_config.DeCommitFreeBlockThreshold, field_size, 1,
                   _file_fp) ||
        1 != fread(&_config.DeCommitTotalFreeThreshold, field_size, 1,
                   _file_fp) ||
        1 != fread(&_config.LockPrefixTable, field_size, 1, _file_fp) ||
        1 != fread(&_config.MaximumAllocationSize, field_size, 1, _file_fp) ||
        1 != fread(&_config.VirtualMemoryThreshold, field_size, 1, _file_fp) ||
        1 != fread(&_config.ProcessAffinityMask, field_size, 1, _file_fp)) {
        return true;
    }

    // Then a few fields have the same size on x86 and x64.
    if (8 != fread(&_config.ProcessHeapFlags, 1, 8, _file_fp)) {
        return true;
    }

    // The last fields have a variable
    // size depending on the architecture again.
    if (1 != fread(&_config.EditList, field_size, 1, _file_fp) ||
        1 != fread(&_config.SecurityCookie, field_size, 1, _file_fp)) {
        return true;
    }
    // The number of bytes read so far
    unsigned int read_bytes = 32 + 8 * field_size;
    // SafeSEH information may not be present in some XP-era binaries.
    // The MSDN page for IMAGE_LOAD_CONFIG_DIRECTORY
    // specifies that their size must be 64
    // (https://msdn.microsoft.com/en-us/
    // library/windows/desktop/ms680328(v=vs.85).aspx).
    // Those fields should be 0 in 64 bit binaries.
    if (_config.Size > read_bytes) {
        if (1 != fread(&_config.SEHandlerTable, field_size, 1, _file_fp) ||
            1 != fread(&_config.SEHandlerCount, field_size, 1, _file_fp)) {
            return true;
        }
    }

    read_bytes += 2 * field_size;
    // Read the remaining fields. The OR operator allows
    // this code to stop whenever a read returns false,
    // i.e. when trying to read more bytes than are
    // available in the structure. This construction is necessary
    // because fields are added to the structure as Windows evolves.
    read_config_field(_config, _file_fp, &_config.GuardCFCheckFunctionPointer,
                      field_size, read_bytes) ||
        read_config_field(_config, _file_fp,
                          &_config.GuardCFDispatchFunctionPointer, field_size,
                          read_bytes) ||
        read_config_field(_config, _file_fp, &_config.GuardCFFunctionTable,
                          field_size, read_bytes) ||
        read_config_field(_config, _file_fp, &_config.GuardCFFunctionCount,
                          field_size, read_bytes) ||
        read_config_field(_config, _file_fp, &_config.GuardFlags, 4,
                          read_bytes) ||
        read_config_field(_config, _file_fp, &_config.CodeIntegrity, 12,
                          read_bytes) ||
        read_config_field(_config, _file_fp,
                          &_config.GuardAddressTakenIatEntryTable, field_size,
                          read_bytes) ||
        read_config_field(_config, _file_fp,
                          &_config.GuardAddressTakenIatEntryCount, field_size,
                          read_bytes) ||
        read_config_field(_config, _file_fp, &_config.GuardLongJumpTargetTable,
                          field_size, read_bytes) ||
        read_config_field(_config, _file_fp, &_config.GuardLongJumpTargetCount,
                          field_size, read_bytes);

    return true;
}

bool MANA_PE::_parse_relocations() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }

    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
        // No relocation table
        return true;
    }

    unsigned int remaining_size =
        _ioh.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    unsigned int header_size = 2 * sizeof(uint32_t);

    while (remaining_size > 0) {
        image_base_relocation reloc;
        if (header_size != fread(&reloc, 1, header_size, _file_fp) ||
            reloc.BlockSize > remaining_size) {
            return false;
        }

        // It seems that sometimes, the end of the
        // section is padded with zeroes. Break here
        // instead of reaching EOF. I have encountered
        // this oddity in 4d7ca8d467770f657305c16474b845fe.
        if (reloc.BlockSize == 0) {
            return true;
        }
        // The remaining fields are an array of shorts.
        // The number is deduced from the block size.
        for (unsigned int i = 0;
             i < (reloc.BlockSize - header_size) / sizeof(uint16_t); ++i) {
            uint16_t type_or_offset = 0;
            if (sizeof(uint16_t) !=
                fread(&type_or_offset, 1, sizeof(uint16_t), _file_fp)) {
                return false;
            }
            reloc.TypesOffsets.push_back(type_or_offset);
        }
        _relocations.push_back(reloc);
        remaining_size -= reloc.BlockSize;
    }
    return true;
}

bool MANA_PE::_parse_debug() {
    /*
    read_unicode_string暂时未实现
     */
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)) {
        // No debug information.
        return true;
    }

    unsigned int size = 6 * sizeof(uint32_t) + 2 * sizeof(uint16_t);
    unsigned int number_of_entries =
        _ioh.directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / size;

    for (unsigned int i = 0; i < number_of_entries; ++i) {
        debug_directory_entry debug;

        if (size != fread(&debug, 1, size, _file_fp)) {
            _err_string = "Could not read an IMAGE_RESOURCE_DATA_ENTRY.";
            return false;
        }
        if (debug.Type ==
            (uint32_t)nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_CODEVIEW")) {
            pdb_info pdb;
            unsigned int pdb_size = 2 * sizeof(uint32_t) + 16 * sizeof(uint8_t);

            unsigned int saved_offset = ftell(_file_fp);
            fseek(_file_fp, debug.PointerToRawData, SEEK_SET);
            if (pdb_size != fread(&pdb, 1, pdb_size, _file_fp) ||
                (pdb.Signature != 0x53445352 && pdb.Signature != 0x3031424E)) {
                // Signature: "RSDS" or "NB10"
                _err_string =
                    "Could not read PDB file information of invalid magic "
                    "number.";
                return false;
            }
            // Not optimal, but it'll help if I decide to
            pdb.PdbFileName = utils::read_ascii_string(_file_fp);
            // further parse these debug sub-structures.
            debug.Filename = pdb.PdbFileName;
            fseek(_file_fp, saved_offset, SEEK_SET);
        } else if (debug.Type ==
                   (uint32_t)nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_MISC")) {
            image_debug_misc misc;
            unsigned int misc_size = 2 * sizeof(uint32_t) + 4 * sizeof(uint8_t);
            unsigned int saved_offset = ftell(_file_fp);
            fseek(_file_fp, debug.PointerToRawData, SEEK_SET);

            if (misc_size != fread(&misc, 1, misc_size, _file_fp)) {
                _err_string = "Could not read DBG file information";
                return false;
            }
            switch (misc.Unicode) {
                case 1:
                    misc.DbgFile = utils::read_unicode_string(
                        _file_fp, misc.Length - misc_size);
                    break;
                case 0:
                    misc.DbgFile = utils::read_ascii_string(
                        _file_fp, misc.Length - misc_size);
                    break;
            }
            debug.Filename = misc.DbgFile;
            fseek(_file_fp, saved_offset, SEEK_SET);
        }
        _debug_entries.push_back(debug);
    }
    return true;
}

bool MANA_PE::_parse_imports() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    // No imports
    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)) {
        return true;
    }

    while (true) {
        image_import_descriptor iid;
        memset(&iid, 0, 5 * sizeof(uint32_t));
        if (20 != fread(&iid, 1, 20, _file_fp)) {
            // Don't give up on the rest of the parsing.
            _err_string = "Could not read the IMAGE_IMPORT_DESCRIPTOR.";
            return true;
        }
        // Exit condition
        if (iid.OriginalFirstThunk == 0 && iid.FirstThunk == 0) {
            break;
        }
        // Non-standard parsing.
        // The Name RVA is translated to an actual string here.
        auto offset = rva_to_offset(iid.Name);
        // Try to use the RVA as a direct address
        // if the imports are outside of a section.
        if (!offset) {
            offset = iid.Name;
        }
        std::string library_name;
        if (!utils::read_string_at_offset(_file_fp, offset, library_name)) {
            if (_imports.size() > 0) {
                break;
            }
            _err_string = "Could not read an import's name.";
            return true;
        }
        iid.import_Name = library_name;
        _imports.push_back(iid);
    }
    // Parse the IMPORT_LOOKUP_TABLE for each imported library
    for (auto it = _imports.begin(); it != _imports.end(); ++it) {
        int ilt_offset;
        if (it->OriginalFirstThunk != 0) {
            ilt_offset = rva_to_offset(it->OriginalFirstThunk);
        } else {
            ilt_offset = rva_to_offset(it->FirstThunk);
        }
        if (!_parse_import_lookup_table(ilt_offset, &(*it))) {
            // Non fatal. Stop trying to parse imports,
            // but the ones already read will still be available.
            return true;
        }
    }
    return true;
}

bool MANA_PE::_parse_delayed_imports() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)) {
        // No delayed imports
        return true;
    }

    memset(&_delay_load_directory_table, 0, 8 * sizeof(uint32_t));
    if (1 != fread(&_delay_load_directory_table, 8 * sizeof(uint32_t), 1,
                   _file_fp)) {
        return true;
    }
    unsigned int offset = rva_to_offset(_delay_load_directory_table.Name);
    if (offset == 0) {
        return true;
    }
    // Read the delayed DLL's name
    std::string name;
    utils::read_string_at_offset(_file_fp, offset, name);
    image_import_descriptor library;
    library.import_Name = name;

    _delay_load_directory_table.NameStr = name;

    // Read the imports
    offset = rva_to_offset(_delay_load_directory_table.DelayImportNameTable);
    if (_parse_import_lookup_table(offset, &library)) {
        _imports.push_back(library);
    }
    return true;
}

bool MANA_PE::_parse_exports() {
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    image_export_directory ied;
    // Don't overwrite the std::string at the end of the structure.
    unsigned int ied_size = 9 * sizeof(uint32_t) + 2 * sizeof(uint16_t);

    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)) {
        // No exports
        return true;
    }

    if (ied_size != fread(&ied, 1, ied_size, _file_fp)) {
        _err_string = "Could not read the IMAGE_EXPORT_DIRECTORY.";
        return false;
    }
    if (ied.Characteristics != 0) {
    }
    if (ied.NumberOfFunctions == 0) {
        // No exports
        return true;
    }
    // Read the export name
    unsigned int offset = rva_to_offset(ied.Name);
    if (!offset ||
        !utils::read_string_at_offset(_file_fp, offset, ied.NameStr)) {
        _err_string = "Could not read the exported DLL name.";
        return false;
    }

    // Get the address and ordinal of each exported function
    offset = rva_to_offset(ied.AddressOfFunctions);
    if (!offset || fseek(_file_fp, offset, SEEK_SET)) {
        _err_string = "Could not reach exported functions address table.";
        return false;
    }
    for (unsigned int i = 0; i < ied.NumberOfFunctions; ++i) {
        exported_function ex;
        memset(&ex, 0, 2 * sizeof(uint32_t));
        if (4 != fread(&(ex.Address), 1, 4, _file_fp)) {
            _err_string = "Could not read an exported function's address.";
            return false;
        }
        ex.Ordinal = ied.Base + i;

        // If the address is located in the export
        // directory, then it is a forwarded export.
        image_data_directory export_dir =
            _ioh.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ex.Address > export_dir.VirtualAddress &&
            ex.Address < export_dir.VirtualAddress + export_dir.Size) {
            offset = rva_to_offset(ex.Address);
            if (!offset || !utils::read_string_at_offset(_file_fp, offset,
                                                         ex.ForwardName)) {
                _err_string = "Could not read an exported function's address.";
                return false;
            }
        }
        _exports.push_back(ex);
    }

    /*
    boost::scoped_array<boost::uint32_t> names;
    boost::scoped_array<boost::uint16_t> ords;
    try
    {
    names.reset(new boost::uint32_t[ied.NumberOfNames]);
    ords.reset(new boost::uint16_t[ied.NumberOfNames]);
    }
    catch (const std::bad_alloc&)
    {
    }
    offset = rva_to_offset(ied.AddressOfNames);
    if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
    {
    return false;
    }

    if (ied.NumberOfNames * sizeof(boost::uint32_t) != fread(names.get(),
     * 1, ied.NumberOfNames * sizeof(boost::uint32_t), _file_handle.get()))
    {
    return false;
    }

    offset = rva_to_offset(ied.AddressOfNameOrdinals);
    if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
    {
    return false;
    }
    if (ied.NumberOfNames * sizeof(boost::uint16_t) != fread(ords.get(),
     * 1, ied.NumberOfNames * sizeof(boost::uint16_t), _file_handle.get()))
    {
            return false;
    }

    // Now match the names with with the exported addresses.
    for (unsigned int i = 0 ; i < ied.NumberOfNames ; ++i)
    {
            offset = rva_to_offset(names[i]);
    if (!offset || ords[i] >= _exports.size()
     * || !utils::read_string_at_offset(_file_handle.get(),
     * offset, _exports.at(ords[i])->Name))
            {

                    return false;
            }
    }

    _ied.reset(ied);
     */

    return true;
}

bool MANA_PE::_parse_resources() {
    /*
        detect_filetype函数暂时没有实现
     */
    if (!_ioh_flag || _file_fp == nullptr) {
        return false;
    }
    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)) {
        // No resources.
        return true;
    }
    image_resource_directory root;
    _read_image_resource_directory(root);
    for (auto it = root.Entries.begin(); it != root.Entries.end(); ++it) {
        image_resource_directory type_ir;
        _read_image_resource_directory(type_ir, it->OffsetToData & 0x7FFFFFFF);
        // Read Name directory
        for (auto it2 = type_ir.Entries.begin(); it2 != type_ir.Entries.end();
             ++it2) {
            image_resource_directory name_ir;
            _read_image_resource_directory(name_ir,
                                           it2->OffsetToData & 0x7FFFFFFF);
            // Read the IMAGE_RESOURCE_DATA_ENTRY
            for (auto it3 = name_ir.Entries.begin();
                 it3 != name_ir.Entries.end(); ++it3) {
                image_resource_data_entry entry;
                memset(&entry, 0, sizeof(image_resource_data_entry));
                unsigned int offset = rva_to_offset(
                    _ioh.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE]
                        .VirtualAddress +
                    (it3->OffsetToData & 0x7FFFFFFF));
                if (!offset || fseek(_file_fp, offset, SEEK_SET)) {
                    _err_string =
                        "Could not reach an IMAGE_RESOURCE_DATA_ENTRY.";
                    return false;
                }
                if (sizeof(image_resource_data_entry) !=
                    fread(&entry, 1, sizeof(image_resource_data_entry),
                          _file_fp)) {
                    _err_string =
                        "Could not read an IMAGE_RESOURCE_DATA_ENTRY.";
                    return false;
                }
                if (entry.Size > _file_size) {
                    continue;
                }
                // Flatten the resource tree.
                std::string name;
                std::string type;
                std::string language;
                int id = 0;

                // Translate resource type.
                // NameOrId is an offset to a string,
                // we already recovered it
                if (it->NameOrId & 0x80000000) {
                    type = it->NameStr;
                } else {
                    // Otherwise, it's a MAKERESOURCEINT constant.
                    type =
                        nt::translate_to_flag(it->NameOrId, nt::RESOURCE_TYPES);
                }
                // Translate resource name
                if (it2->NameOrId & 0x80000000) {
                    name = it2->NameStr;
                } else {
                    id = it2->NameOrId;
                }

                // Translate the language.
                if (it3->NameOrId & 0x80000000) {
                    language = it3->NameStr;
                } else {
                    language =
                        nt::translate_to_flag(it3->NameOrId, nt::LANG_IDS);
                }
                offset = rva_to_offset(entry.OffsetToData);
                if (!offset) {
                    if (id) {
                        std::cerr << id;
                    } else {
                        std::cerr << name;
                    }
                    offset = entry.OffsetToData;
                }

                // Resource res;
                if (entry.Size == 0) {
                    /*
                    if (name != "") {

                    } else {

                    }
                     */
                    continue;
                }

                // Sanity check: verify that no resource
                // is already pointing to the given offset.
                bool is_malformed =
                    std::any_of(_resources.begin(), _resources.end(),
                                [offset, &entry](const auto& res) {
                                    return res.get_offset() == offset &&
                                           res.get_size() == entry.Size;
                                });
                if (is_malformed) {
                    // Duplicate resource. Do not add it again.
                    continue;
                }
                if (name != "") {
                    Resource res(type, name, language, entry.Codepage,
                                 entry.Size, offset, _path, _file_fp);
                    _resources.push_back(res);
                } else {
                    Resource res(type, id, language, entry.Codepage, entry.Size,
                                 offset, _path, _file_fp);
                    _resources.push_back(res);
                }
            }
        }
    }
    return true;
}

bool MANA_PE::_parse_section_table() {
    if (!_h_pe_flag || !_h_dos_flag || _file_fp == nullptr) {
        return false;
    }

    if (fseek(_file_fp,
              _h_dos.e_lfanew + sizeof(pe_header) + _h_pe.SizeOfOptionalHeader,
              SEEK_SET)) {
        _err_string = "Could not reach the Section Table ";
        return false;
    }
    for (int i = 0; i < _h_pe.NumberofSections; ++i) {
        image_section_header sec;
        memset(&sec, 0, sizeof(image_section_header));
        if (sizeof(image_section_header) !=
            fread(&sec, 1, sizeof(image_section_header), _file_fp)) {
            _err_string = "Could not read section " + i;
            return false;
        }
        // _sections.push_back(boost::make_shared<Section>(sec,
        // _file_handle, _file_size, _coff_string_table));
        // here should deal the section.Name
        _sections.push_back(sec);
    }
    return true;
}

bool MANA_PE::_parse_dos_header() {
    if (_file_fp == nullptr) {
        return false;
    }

    memset(&_h_dos, 0, sizeof(_h_dos));
    if (sizeof(_h_dos) > get_filesize()) {
        _err_string = "Input file is too small to be a valid PE.";
        return false;
    }

    if (sizeof(_h_dos) != fread(&_h_dos, 1, sizeof(_h_dos), _file_fp)) {
        _err_string = "Could not read the DOS Header.";
        return false;
    }

    if (_h_dos.e_magic[0] != 'M' || _h_dos.e_magic[1] != 'Z') {
        _err_string = "DOS Header is invalid (wrong magic).";
        return false;
    }
    return true;
}

bool MANA_PE::_parse_pe_header() {
    if (_file_fp == nullptr) {
        return false;
    }

    memset(&_h_pe, 0, sizeof(_h_pe));
    if (fseek(_file_fp, _h_dos.e_lfanew, SEEK_SET)) {
        _err_string = "Could not reach PE header (fseek to offset failed).";
        return false;
    }
    if (sizeof(_h_pe) != fread(&_h_pe, 1, sizeof(_h_pe), _file_fp)) {
        _err_string = "Could not read the PE Header.";
        return false;
    }
    if (_h_pe.Signature[0] != 'P' || _h_pe.Signature[1] != 'E' ||
        _h_pe.Signature[2] != '\x00' || _h_pe.Signature[3] != '\x00') {
        _err_string = "PE Header is invalid.";
        return false;
    }
    return true;
}

bool MANA_PE::_parse_coff_symbols() {
    if (!_h_pe_flag || _file_fp == nullptr) {
        return false;
    }

    if (_h_pe.NumberOfSymbols == 0 || _h_pe.PointerToSymbolTable == 0) {
        return true;
    }
    if (fseek(_file_fp, _h_pe.PointerToSymbolTable, SEEK_SET)) {
        _err_string = "Could not reach PE COFF symbols (fseek to offset ";
        return false;
    }
    for (unsigned int i = 0; i < _h_pe.NumberOfSymbols; ++i) {
        coff_symbol sym;
        memset(&sym, 0, sizeof(coff_symbol));

        if (18 != fread(&sym, 1, 18, _file_fp)) {
            // Each symbol has a fixed size of 18 bytes.
            _err_string = "Could not read a COFF symbol.";
            return false;
        }

        if (sym.SectionNumber > _sections.size()) {
            continue;
        }
        _coff_symbols.push_back(sym);
    }
    // Read the COFF string table
    uint32_t st_size = 0;
    uint32_t count = 0;
    fread(&st_size, 4, 1, _file_fp);
    // Weak error check, but I couldn't find a better one in the PE spec.
    if (st_size > get_filesize() - ftell(_file_fp)) {
        return false;
    }
    while (count < st_size) {
        // original is the utils::read_ascii_string(f)
        std::string s = std::string();
        char c = 0;
        while (1 == fread(&c, 1, 1, _file_fp)) {
            if (c == '\0') {
                break;
            }
            s += c;
        }

        _coff_string_table.push_back(s);
        // Count the null terminator as well.
        count = count + (uint32_t)s.size() + 1;
    }
    return true;
}

bool MANA_PE::_parse_image_optional_header() {
    if (_file_fp == nullptr) {
        return false;
    }

    memset(&_ioh, 0, sizeof(_ioh));
    if (_h_pe.SizeOfOptionalHeader == 0) {
        _err_string = "This PE has no Image Optional Header!.";
        return true;
    }
    if (fseek(_file_fp, _h_dos.e_lfanew + sizeof(pe_header), SEEK_SET)) {
        _err_string = "Could not reach the Image Optional Header";
        return false;
    }
    // Only read the first 0x18 bytes: after that,
    // we have to fill the fields manually.
    if (0x18 != fread(&_ioh, 1, 0x18, _file_fp)) {
        _err_string = "Could not read the Image Optional Header.";
        return false;
    }
    if (_ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32"] &&
        _ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32+"]) {
        _err_string = "Invalid Image Optional Header magic.";
        return false;
    } else if (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32"]) {
        if (4 != fread(&_ioh.BaseOfData, 1, 4, _file_fp) ||
            4 != fread(&_ioh.ImageBase, 1, 4, _file_fp)) {
            _err_string =
                "Error reading the PE32 specific part of ImageOptionalHeader.";
            return false;
        }
    } else {
        // PE32+: BaseOfData doesn't exist, and ImageBase is a uint64.
        if (8 != fread(&_ioh.ImageBase, 1, 8, _file_fp)) {
            _err_string =
                "Error reading the PE32+ specific part of ImageOptionalHeader.";
            return false;
        }
    }

    // After this, PE32 and PE32+ structures are in sync for a while.
    if (0x28 != fread(&_ioh.SectionAlignment, 1, 0x28, _file_fp)) {
        _err_string = "Error reading the common part of ImageOptionalHeader.";
        return false;
    }
    // Reject malformed executables
    if (_ioh.FileAlignment == 0 || _ioh.SectionAlignment == 0) {
        _err_string =
            "FileAlignment or SectionAlignment is null: the PE is invalid.";
        return false;
    }
    // The next 4 values may be uint32s or uint64s
    // depending on whether this is a PE32+ header.
    // We store them in uint64s in any case.
    if (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32+"]) {
        if (40 != fread(&_ioh.SizeofStackReserve, 1, 40, _file_fp)) {
            _err_string = std::string("Error reading SizeOfStackReserve for") +
                          "a PE32+ IMAGE OPTIONAL HEADER.";
            return false;
        }
    } else {
        fread(&_ioh.SizeofStackReserve, 1, 4, _file_fp);
        fread(&_ioh.SizeofStackCommit, 1, 4, _file_fp);
        fread(&_ioh.SizeofHeapReserve, 1, 4, _file_fp);
        fread(&_ioh.SizeofHeapCommit, 1, 4, _file_fp);
        fread(&_ioh.LoaderFlags, 1, 4, _file_fp);
        fread(&_ioh.NumberOfRvaAndSizes, 1, 4, _file_fp);
        if (feof(_file_fp) || ferror(_file_fp)) {
            _err_string = std::string("Error reading SizeOfStackReserve ") +
                          " for a PE32 IMAGE OPTIONAL HEADER.";
            return false;
        }
    }
    if (_ioh.NumberOfRvaAndSizes > 0x10) {
    }
    for (unsigned int i = 0;
         i < std::min(_ioh.NumberOfRvaAndSizes, (uint32_t)(0x10)); ++i) {
        if (8 != fread(&_ioh.directories[i], 1, 8, _file_fp)) {
            _err_string = "Could not read directory entry " + i;
            return false;
        }
    }
    return true;
}

bool MANA_PE::is_address_in_section(uint64_t rva,
                                    const image_section_header& section,
                                    bool check_raw_size) {
    if (!check_raw_size) {
        return section.VirtualAddress <= rva &&
               rva < section.VirtualAddress + section.VirtualSize;
    } else {
        return section.VirtualAddress <= rva &&
               rva < section.VirtualAddress + section.SizeOfRawData;
    }
}

bool MANA_PE::find_section(unsigned int rva, image_section_header& res) {
    if (!_initialized) {
        return false;
    }
    bool find = false;
    memset(&res, 0, sizeof(res));
    auto it1 = std::find_if(_sections.begin(), _sections.end(),
                            [&](const auto& section) {
                                return is_address_in_section(rva, section);
                            });

    if (it1 != _sections.end()) {
        res = *it1;
        find = true;
    }
    // VirtualSize may be erroneous. Check with RawSizeofData.
    if (!find) {
        auto it2 = std::find_if(
            _sections.begin(), _sections.end(), [&](const auto& section) {
                return is_address_in_section(rva, section, true);
            });

        if (it2 != _sections.end()) {
            res = *it2;
            find = true;
        }
    }
    return find;
}

bool MANA_PE_EXT::parse_pe(const std::wstring& path, uint32_t parse_flag) {
    FILE* f = _file_fp;
    if (!f) {
        f = _wfsopen(path.c_str(), L"rb", _SH_DENYNO);
    }
    if (f == nullptr) {
        _err_string = "open the file failed";
        return false;
    }
    _parse_flag = parse_flag;
    _file_fp = f;
    fseek(f, 0, SEEK_END);
    _file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (_parse_flag & MANA_PE_PARSE_DOS_HEADER) {
        if (_h_dos_flag == false) {
            _h_dos_flag = _parse_dos_header();
            if (!_h_dos_flag) {
                return false;
            }
        }
    }
    if (_parse_flag & MANA_PE_PARSE_PE_HEADER) {
        if (_h_pe_flag == false) {
            _h_pe_flag = _parse_pe_header();
            if (!_h_pe_flag) {
                return false;
            }
        }
    }
    if (_parse_flag & MANA_PE_PARSE_IO_HEADER) {
        if (_ioh_flag == false) {
            _ioh_flag = _parse_image_optional_header();
            if (!_ioh_flag) {
                return false;
            }
        }
    }
    if (_parse_flag & MANA_PE_PARSE_SECTION_TABLE) {
        if (!_parse_section_table()) {
            return false;
        }
    }

    if (_parse_flag & MANA_PE_PARSE_COFF_SYSBOLS) {
        _parse_coff_symbols();
    }

    return _parse_directories();
}
}  // namespace mana
