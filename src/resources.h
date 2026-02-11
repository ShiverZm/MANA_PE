#pragma once
#ifndef SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_RESOURCES_H_
#define SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_RESOURCES_H_

#include <string>
#include <vector>
#include <sstream>

#include "./utils.h"

namespace mana {

class Resource {
 public:
    Resource(const std::string& type, const std::string& name,
             const std::string& language, uint32_t codepage, uint32_t size,
             uint32_t offset_in_file, const std::wstring& path_to_pe,
             FILE* file_fp)
        : _type(type),
          _file_fp(file_fp),
          _name(name),
          _language(language),
          _codepage(codepage),
          _size(size),
          _offset_in_file(offset_in_file),
          _path_to_pe(path_to_pe) {}

    Resource(const std::string& type, uint32_t id, const std::string& language,
             uint32_t codepage, uint32_t size, uint32_t offset_in_file,
             const std::wstring& path_to_pe, FILE* file_fp)
        : _type(type),
          _file_fp(file_fp),
          _name(""),
          _id(id),
          _language(language),
          _codepage(codepage),
          _size(size),
          _offset_in_file(offset_in_file),
          _path_to_pe(path_to_pe) {}

    virtual ~Resource() {}

    const std::string& get_type() const { return _type; }

    const std::string& get_language() const { return _language; }

    uint32_t get_codepage() const { return _codepage; }

    uint32_t get_size() const { return _size; }

    uint32_t get_id() const { return _id; }

    uint32_t get_offset() const { return _offset_in_file; }

    double get_entropy() const {
        return utils::shannon_entropy(get_raw_data());
    }
    std::vector<uint8_t> get_raw_data() const;

    template <class T>
    T interpret_as();

 private:
    std::string _type;
    FILE* _file_fp = nullptr;
    // Resources can either have an identifier or a name.
    std::string _name;
    uint32_t _id = 0;

    std::string _language;
    uint32_t _codepage = 0;
    uint32_t _size = 0;

    // These fields do not describe the PE structure.
    unsigned int _offset_in_file = 0;
    std::wstring _path_to_pe;
};
}  // namespace mana
#endif  // SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_RESOURCES_H_
