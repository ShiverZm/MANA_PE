#ifndef SRC_PE_ATTRIBUTES_INCLUDE_DUMP_PE_DUMP_H_
#define SRC_PE_ATTRIBUTES_INCLUDE_DUMP_PE_DUMP_H_

#include "PE_structs.h"
namespace mana {
dos_header_str dump_dos_header(dos_header dos);
pe_header_str dump_pe_header(pe_header peh);
}  // namespace mana

#endif  // SRC_PE_ATTRIBUTES_INCLUDE_DUMP_PE_DUMP_H_
