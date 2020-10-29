#ifndef INCLUDE_MPEE_UTIL
#define INCLUDE_MPEE_UTIL

#include "main.h"

namespace Util{
    template<typename T>
    void LoadPEStructure(std::fstream&, T*, int offset=0, bool rewind=false);
    std::vector<char> LoadPEData(const char*);
    char Pause();
    char Pause(std::string);
}
#include "util.hpp"

#endif // INCLUDE_MPEE_UTIL
