//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/blueprint/zkevm/zkevm_word.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace nil {
    namespace blueprint {
        std::vector<zkevm_word_type> zkevm_word_vector_from_ptree(const boost::property_tree::ptree &ptree){
            std::vector<zkevm_word_type> result;
            for(auto it = ptree.begin(); it != ptree.end(); it++){
                result.push_back(zkevm_word_from_string(it->second.data()));
            }
            return result;
        }

        std::map<zkevm_word_type, zkevm_word_type> key_value_storage_from_ptree(const boost::property_tree::ptree &ptree){
            std::map<zkevm_word_type, zkevm_word_type> result;
//              std::cout << "Storage:" << std::endl;
            for(auto it = ptree.begin(); it != ptree.end(); it++){
                result[zkevm_word_from_string(it->first.data())] = zkevm_word_from_string(it->second.data());
//                    std::cout << "\t" << it->first.data() << "=>" <<  it->second.data() << std::endl;
            }
            return result;
        }

        std::vector<std::uint8_t> byte_vector_from_ptree(const boost::property_tree::ptree &ptree){
            std::vector<std::uint8_t> result;
//                std::cout << "MEMORY words " << ptree.size() << ":";
            for(auto it = ptree.begin(); it != ptree.end(); it++){
                for(std::size_t i = 0; i < it->second.data().size(); i+=2){
                    std::uint8_t byte = char_to_hex(it->second.data()[i]) * 16 + char_to_hex(it->second.data()[i+1]);
//                        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::size_t(byte) << " ";
                    result.push_back(byte);
                }
            }
//                std::cout << std::endl;
            return result;
        }
    }
}
