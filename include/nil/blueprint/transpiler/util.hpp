#ifndef __TRANSPILER_UTIL_HPP__
#define __TRANSPILER_UTIL_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <boost/algorithm/string.hpp> 

namespace nil {
    namespace blueprint {
        using transpiler_replacements = std::map<std::string, std::string>;

        template<typename T> std::string to_string(T val) {
            std::stringstream strstr;
            strstr << val;
            return strstr.str();
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__