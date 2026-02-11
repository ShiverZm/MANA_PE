#include "utils.h"
#include "utf8.h"
#include <string>
#include <stdint.h>
#include <vector>
namespace utils {

std::string read_ascii_string(FILE* f, unsigned int max_bytes) {
    std::string s;
    char c = 0;
    while (1 == fread(&c, 1, 1, f)) {
        if (c == '\0') {
            break;
        }
        s += c;
        // Already 0 if no limit.
        if (max_bytes != 0) {
            --max_bytes;
            // <= Just in case someone thin
            if (!max_bytes) {
                break;
            }
        }
    }

    return s;
}

std::wstring read_prefixed_unicode_wstring(FILE* f) {
    std::wstring s = std::wstring();
    wchar_t c = 0;
    uint16_t size;
    if (2 != fread(&size, 1, 2, f)) {
        return L"";
    }

    for (unsigned int i = 0; i < size; ++i) {
        if (2 != fread(&c, 1, 2, f)) {
            break;
        }
        s += c;
    }
    return s;
}

std::string read_prefixed_unicode_string(FILE* f) {
    std::wstring s = read_prefixed_unicode_wstring(f);

    try {
        std::vector<uint8_t> utf8result;
        utf8::utf16to8(s.begin(), s.end(), std::back_inserter(utf8result));
        return std::string(utf8result.begin(), utf8result.end());
    } catch (utf8::invalid_utf16) {
    }

    return "";
}

bool read_string_at_offset(FILE* f, unsigned int offset, std::string& out,
                           bool unicode) {
    unsigned int saved_offset = ftell(f);
    if (saved_offset == -1 || fseek(f, offset, SEEK_SET)) {
        return false;
    }
    if (!unicode) {
        out = read_ascii_string(f);
    } else {
        out = read_prefixed_unicode_string(f);
    }

    return !fseek(f, saved_offset, SEEK_SET) && out != "";
}

double shannon_entropy(const std::vector<uint8_t>& bytes) {
    int frequency[256] = {0};
    for (auto it = bytes.begin(); it != bytes.end(); ++it) {
        frequency[*it] += 1;
    }

    double res = 0.;
    double size = static_cast<double>(bytes.size());
    for (int i = 0; i < 256; ++i) {
        if (frequency[i] == 0) {
            continue;
        }
        double freq = static_cast<double>(frequency[i]) / size;
        res -= freq * log(freq) / log(2.);
    }

    return res;
}

std::string read_unicode_string(FILE* f, unsigned int max_bytes) {
    std::wstring s = std::wstring();
    wchar_t c = 0;
    while (2 == fread(&c, 1, 2, f)) {
        if (c == '\0') {
            break;
        }
        s += c;
        if (max_bytes != 0) {
            // Already 0 if no limit.
            max_bytes -= 2;
            if (max_bytes <= 1) {
                break;
            }
        }
    }

    try {
        std::vector<uint8_t> utf8result;
        utf8::utf16to8(s.begin(), s.end(), std::back_inserter(utf8result));
        return std::string(utf8result.begin(), utf8result.end());
    } catch (utf8::invalid_utf16) {
    }

    return "";
}

}  // namespace utils
