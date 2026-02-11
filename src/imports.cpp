//#include "common/Utils.h"
#include "mana_pe.h"
#include "PE_structs.h"
#include "utils.h"
namespace mana {

bool MANA_PE::_parse_hint_name_table(import_lookup_table *import) {
    int size_to_read = (get_architecture() == MANA_PE::x86 ? 4 : 8);

    // Read the HINT/NAME TABLE if applicable.
    // Check the most significant byte of AddressOfData to
    // see if the import is by name or ordinal.
    // For PE32+, AddressOfData is a uint64.
    uint64_t mask = (size_to_read == 8 ? 0x8000000000000000 : 0x80000000);

    if (!(import->AddressOfData & mask)) {
        // Import by name. Read the HINT/NAME table.
        // For both PE32 and PE32+, its RVA is stored
        // in bits 30-0 of AddressOfData.
        unsigned int table_offset =
            rva_to_offset(import->AddressOfData & 0x7FFFFFFF);
        if (table_offset == 0) {
            return false;
        }

        unsigned int saved_offset = ftell(_file_fp);
        if (saved_offset == -1 || fseek(_file_fp, table_offset, SEEK_SET) ||
            2 != fread(&(import->Hint), 1, 2, _file_fp)) {
            return false;
        }

        import->Name = utils::read_ascii_string(_file_fp);
        // Go back to the import lookup table.
        if (fseek(_file_fp, saved_offset, SEEK_SET)) {
            return false;
        }
    }
    return true;
}

bool MANA_PE::_parse_import_lookup_table(unsigned int offset,
                                         image_import_descriptor *library) {
    if (!offset || fseek(_file_fp, offset, SEEK_SET)) {
        return false;
    }
    import_lookup_table import;
    while (true) {
        import.AddressOfData = 0;
        import.Hint = 0;
        // The field has a size of 8 for x64 PEs
        int size_to_read = (get_architecture() == x86 ? 4 : 8);
        if (size_to_read !=
            (int)fread(&(import.AddressOfData), 1, size_to_read, _file_fp)) {
            return false;
        }
        // Exit condition
        if (import.AddressOfData == 0) {
            break;
        }

        if (!_parse_hint_name_table(&import)) {
            return false;
        }
        if (import.Name == "") {
            std::stringstream ss;
            ss << "#" << (import.AddressOfData & 0x7FFF);
            import.Name = ss.str();
        }
        library->import_lookup.push_back(import);
    }
    return true;
}
}  // namespace mana
