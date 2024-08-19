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
#include <iostream>
//#include <boost/algorithm/string.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>

namespace nil {
    namespace blueprint {
        using transpiler_replacements = std::map<std::string, std::string>;

        template<typename T> std::string to_string(T val) {
            std::stringstream strstr;
            strstr << val;
            return strstr.str();
        }

        template<typename T> std::string to_hex_string(T val) {
            std::stringstream strstr;
            strstr << std::hex << val << std::dec;
            return strstr.str();
        }

        static inline std::string rot_string (int j, std::size_t rows_amount, std::string mode){
            int abs_j = j>0? j: -j;
            int other_j = rows_amount - abs_j;
            if(other_j < abs_j) {
                j = j > 0? -other_j: other_j;
            }

            if( mode == "recursive"){
                if(j == 0) return "xi"; else
                if(j == 1 ) return "xi*omega"; else
                if(j == -1) return "xi/omega"; else
                if(j > 0) return "xi*pow< " + to_string(j) + ">(omega)"; else
                if(j < 0) return "xi/pow< " + to_string(-j) + ">(omega)";
            } else if(mode == "evm") {
                if(j == 0) return "xi"; else
                if(j == 1 ) return "mulmod(xi, omega, modulus)"; else
                if(j == -1) return "mulmod(xi, inversed_omega, modulus)"; else
                if(j > 0) return "mulmod(xi, field.pow_small(omega, " + to_string(j) + ", modulus), modulus)"; else
                if(j < 0) return "mulmod(xi, field.pow_small(inversed_omega, " + to_string(-j) + ", modulus), modulus)";
            }
            return "";
        }

        void replace_and_print(std::string input, transpiler_replacements reps, std::string output_file_name){
            std::string code = input;

            for(const auto&[k,v]: reps){
                boost::replace_all(code, k, v);
            }
            for(const auto&[k,v]: reps){
                boost::replace_all(code, k, v);
            }
            std::ofstream out;
            out.open(output_file_name);
            out << code;
            out.close();
        }

        std::string replace_all(std::string input, transpiler_replacements reps){
            std::string code = input;

            for(const auto&[k,v]: reps){
                boost::replace_all(code, k, v);
            }

            return code;
        }


        // Tuple of singles, poly ids with singles>
        template<typename PlaceholderParams, typename CommonDataType>
        static std::tuple<std::vector<std::size_t>, std::vector<std::string>, std::map<std::string, std::size_t>, std::vector<std::vector<std::size_t>>>
        calculate_unique_points(
            const zk::snark::placeholder_info<PlaceholderParams>  &placeholder_info,
            zk::snark::plonk_table_description<typename PlaceholderParams::field_type> desc,
            const CommonDataType &common_data,
            std::size_t permutation_size,
            std::size_t quotient_size,
            std::size_t sorted_size,
            std::string mode
        ){
            std::vector<std::size_t> z_points_indices;
            std::vector<std::string> singles;
            std::map<std::string, std::size_t> singles_map;
            std::vector<std::vector<std::size_t>> poly_ids;
            std::size_t rows_amount = common_data.desc.rows_amount;

            singles.push_back(rot_string(0, rows_amount, mode));
            singles_map[rot_string(0, rows_amount, mode)] = singles_map.size();
            poly_ids.resize(singles.size());

            // Sigma and permutation polys
            std::size_t count = 0;
            for( std::size_t i = 0; i < placeholder_info.permutation_size; i++){
                poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count+1);
                z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                count += 2;
            }

            // Special selectors
            singles.push_back(rot_string(1, rows_amount, mode));
            singles_map[rot_string(1, rows_amount, mode)] = singles_map.size();
            poly_ids.resize(singles.size());

            poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
            poly_ids[singles_map[rot_string(1, rows_amount, mode)]].push_back(count);
            z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
            z_points_indices.push_back(singles_map[rot_string(1, rows_amount, mode)]);
            count++;
            poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
            poly_ids[singles_map[rot_string(1, rows_amount, mode)]].push_back(count);
            z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
            z_points_indices.push_back(singles_map[rot_string(1, rows_amount, mode)]);
            count++;

            for(std::size_t i = 0; i < desc.constant_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i + desc.witness_columns + desc.public_input_columns]){
                    if(singles_map.find(rot_string(j, rows_amount, mode)) == singles_map.end()){
                        singles_map[rot_string(j, rows_amount, mode)] = singles_map.size();
                        singles.push_back(rot_string(j, rows_amount, mode));
                        poly_ids.resize(singles.size());
                    }
                    poly_ids[singles_map[rot_string(j, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(j, rows_amount, mode)]);
                }
                count++;
            }

            for(std::size_t i = 0; i < desc.selector_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i + desc.witness_columns + desc.public_input_columns + desc.constant_columns]){
                    if(singles_map.find(rot_string(j, rows_amount, mode)) == singles_map.end()){
                        singles_map[rot_string(j, rows_amount, mode)] = singles_map.size();
                        singles.push_back(rot_string(j, rows_amount, mode));
                        poly_ids.resize(singles.size());
                    }
                    poly_ids[singles_map[rot_string(j, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(j, rows_amount, mode)]);
                }
                count++;
            }

            for(std::size_t i = 0; i < desc.witness_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i]){
                    if(singles_map.find(rot_string(j, rows_amount, mode)) == singles_map.end()){
                        singles_map[rot_string(j, rows_amount, mode)] = singles_map.size();
                        singles.push_back(rot_string(j, rows_amount, mode));
                        poly_ids.resize(singles.size());
                    }
                    poly_ids[singles_map[rot_string(j, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(j, rows_amount, mode)]);
                }
                count++;
            }

            for(std::size_t i = 0; i < desc.public_input_columns; i++){
                std::stringstream str;
                for(auto j:common_data.columns_rotations[i + desc.witness_columns]){
                    if(singles_map.find(rot_string(j, rows_amount, mode)) == singles_map.end()){
                        singles_map[rot_string(j, rows_amount, mode)] = singles_map.size();
                        singles.push_back(rot_string(j, rows_amount, mode));
                        poly_ids.resize(singles.size());
                    }
                    poly_ids[singles_map[rot_string(j, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(j, rows_amount, mode)]);
                }
                count++;
            }

            // Permutation argument
            if( placeholder_info.use_permutations ){
                poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                poly_ids[singles_map[rot_string(1, rows_amount, mode)]].push_back(count);
                z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                z_points_indices.push_back(singles_map[rot_string(1, rows_amount, mode)]);
                count++;
                for(std::size_t i = 0; i < placeholder_info.permutation_poly_amount - 1; i++ ){
                    poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                    count++;
                }
            }

            // Lookup permutation
            if(placeholder_info.use_lookups){
                poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                poly_ids[singles_map[rot_string(1, rows_amount, mode)]].push_back(count);
                z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                z_points_indices.push_back(singles_map[rot_string(1, rows_amount, mode)]);
                count++;
                for(std::size_t i = 0; i < placeholder_info.lookup_poly_amount - 1; i++ ){
                    poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                    count++;
                }
            }

            // Quotient
            for(std::size_t i = 0; i < placeholder_info.quotient_size; i++){
                poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                count++;
            }

            // Lookup batch
            if(placeholder_info.use_lookups){
                if(singles_map.find(rot_string(common_data.desc.usable_rows_amount, rows_amount, mode)) == singles_map.end()){
                    singles_map[rot_string(common_data.desc.usable_rows_amount, rows_amount, mode)] = singles.size();
                    singles.push_back(rot_string(common_data.desc.usable_rows_amount, rows_amount, mode));
                    poly_ids.resize(singles.size());
                }
                for( std::size_t i = 0; i < sorted_size; i++ ){
                    poly_ids[singles_map[rot_string(0, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(0, rows_amount, mode)]);
                    poly_ids[singles_map[rot_string(1, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(1, rows_amount, mode)]);
                    poly_ids[singles_map[rot_string(common_data.desc.usable_rows_amount, rows_amount, mode)]].push_back(count);
                    z_points_indices.push_back(singles_map[rot_string(common_data.desc.usable_rows_amount, rows_amount, mode)]);
                    count++;
                }
            }

            return std::make_tuple(z_points_indices, singles, singles_map, poly_ids);
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__