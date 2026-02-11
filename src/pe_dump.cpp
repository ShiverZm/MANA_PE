#include "PE_structs.h"
#include "mana_pe.h"
#include "nt_values.h"
#include <string.h>
namespace mana {

dos_header_str dump_dos_header(dos_header dos) {
    dos_header_str ret_dos;
    memset(&ret_dos, 0, sizeof(ret_dos));

    sprintf_s(ret_dos.e_magic, sizeof(ret_dos.e_magic), "%c%c", dos.e_magic[0],
              dos.e_magic[1]);
    sprintf_s(ret_dos.e_cblp, sizeof(ret_dos.e_cblp), "0x%x", dos.e_cblp);
    sprintf_s(ret_dos.e_cp, sizeof(ret_dos.e_cp), "0x%x", dos.e_cp);
    sprintf_s(ret_dos.e_crlc, sizeof(ret_dos.e_crlc), "0x%x", dos.e_crlc);
    sprintf_s(ret_dos.e_cparhdr, sizeof(ret_dos.e_cparhdr), "0x%x",
              dos.e_cparhdr);
    sprintf_s(ret_dos.e_minalloc, sizeof(ret_dos.e_minalloc), "0x%x",
              dos.e_minalloc);
    sprintf_s(ret_dos.e_maxalloc, sizeof(ret_dos.e_maxalloc), "0x%x",
              dos.e_maxalloc);
    sprintf_s(ret_dos.e_ss, sizeof(ret_dos.e_ss), "0x%x", dos.e_ss);
    sprintf_s(ret_dos.e_sp, sizeof(ret_dos.e_sp), "0x%x", dos.e_sp);
    sprintf_s(ret_dos.e_csum, sizeof(ret_dos.e_csum), "0x%x", dos.e_csum);
    sprintf_s(ret_dos.e_ip, sizeof(ret_dos.e_ip), "0x%x", dos.e_ip);
    sprintf_s(ret_dos.e_cs, sizeof(ret_dos.e_cs), "0x%x", dos.e_cs);
    sprintf_s(ret_dos.e_ovno, sizeof(ret_dos.e_ovno), "0x%x", dos.e_ovno);
    sprintf_s(ret_dos.e_oemid, sizeof(ret_dos.e_oemid), "0x%x", dos.e_oemid);
    sprintf_s(ret_dos.e_oeminfo, sizeof(ret_dos.e_oeminfo), "0x%x",
              dos.e_oeminfo);
    sprintf_s(ret_dos.e_lfanew, sizeof(ret_dos.e_lfanew), "0x%x", dos.e_lfanew);
    return ret_dos;
}

pe_header_str dump_pe_header(pe_header peh) {
    pe_header_str ret_peh;
    memset(&ret_peh, 0, sizeof(ret_peh));

    sprintf_s(ret_peh.Signature, sizeof(ret_peh.Signature), "%c%c",
              peh.Signature[0], peh.Signature[1]);
    sprintf_s(ret_peh.Machine, sizeof(ret_peh.Machine), "%s",
              nt::translate_to_flag(peh.Machine, nt::MACHINE_TYPES).c_str());
    ret_peh.NumberofSections = peh.NumberofSections;
    sprintf_s(ret_peh.TimeDateStamp, sizeof(ret_peh.TimeDateStamp), "%s",
              nt::timestamp_to_string(peh.TimeDateStamp).c_str());
    sprintf_s(ret_peh.PointerToSymbolTable,
              sizeof(ret_peh.PointerToSymbolTable), "0x%x",
              peh.PointerToSymbolTable);
    ret_peh.NumberOfSymbols = peh.NumberOfSymbols;
    sprintf_s(ret_peh.SizeOfOptionalHeader,
              sizeof(ret_peh.SizeOfOptionalHeader), "0x%x",
              peh.SizeOfOptionalHeader);
    return ret_peh;
}
}  // namespace mana
