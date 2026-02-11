#pragma once
#ifndef SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_UTILS_H_
#define SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_UTILS_H_
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <iostream>
#include <string.h>
#include <math.h>
#include <vector>
#include <stdint.h>

namespace utils {
std::string read_ascii_string(FILE* f, unsigned int max_bytes = 0);
bool read_string_at_offset(FILE* f, unsigned int offset, std::string& out,
                           bool unicode = false);
double shannon_entropy(const std::vector<uint8_t>& bytes);
std::string read_unicode_string(FILE* f, unsigned int max_bytes = 0);
}  // namespace utils
#endif  // SRC_PE_ATTRIBUTES_INCLUDE_MANAPE_UTILS_H_
