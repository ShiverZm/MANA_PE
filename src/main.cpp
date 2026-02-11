#include <windows.h>
#include <string.h>
#include "mana_pe.h"
#include "resources.h"

int main() {

  int ret = 0;
  std::wstring file_path = L"F:\\Download\\Clash.Verge_2.0.3_x64-setup.exe";
  mana::MANA_PE_EXT win_pe;
  do {
    if (!win_pe.parse_pe(file_path,
                         MANA_PE_PARSE_DOS_HEADER | MANA_PE_PARSE_PE_HEADER)) {
      break;
    }
    mana::pe_header pe_header = win_pe.get_pe_header();

    if (!win_pe.parse_pe(file_path,
                         MANA_PE_PARSE_DOS_HEADER | MANA_PE_PARSE_PE_HEADER |
                             MANA_PE_PARSE_IO_HEADER |
                             MANA_PE_PARSE_SECTION_TABLE |
                             MANA_PE_PARSE_IMPORTS | MANA_PE_PARSE_RESOURCES)) {
      break;
    }

    std::vector<mana::Resource> pe_resources =
        win_pe.get_resources();

    for (auto item : pe_resources) {
        if (item.get_type() == "RT_MANIFEST") {
            uint32_t resource_id = item.get_id();
            printf("resource type: %s, ID: %u\n", item.get_type().c_str(), resource_id);

            size_t offset_in_file = item.get_offset();
            FILE* pfile = win_pe.get_obj_file_fp();

            fseek(pfile, 0, SEEK_SET);
            fseek(pfile, offset_in_file, SEEK_SET);

            char buff[1024 * 10] = { 0 };
            fread(buff, 1, sizeof(buff), pfile);
            printf("%s\n", buff);

            std::string xml(buff);
            if (xml.find("name=\"Nullsoft.NSIS.exehead\"")){
                printf("it is NSIS setup file\n");
            }
            break;
        }
    }
    
  } while (false);
  
  system("pause");
  return 0;
}
