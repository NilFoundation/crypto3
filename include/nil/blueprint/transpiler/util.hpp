//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//
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

        void replace_and_print(std::string input, transpiler_replacements reps, std::string output_file_name){
            std::string code = input;

            for(const auto&[k,v]: reps){
                boost::replace_all(code, k, v);
            }
            std::ofstream out;
            out.open(output_file_name);
            out << code;
            out.close();
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__