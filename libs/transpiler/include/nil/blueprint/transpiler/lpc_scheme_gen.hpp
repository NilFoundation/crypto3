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
#ifndef __LPC_SCHEME_GEN_HPP__
#define __LPC_SCHEME_GEN_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <boost/algorithm/string.hpp>
#include <nil/blueprint/transpiler/util.hpp>
#include <nil/blueprint/transpiler/templates/commitment_scheme.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>

namespace nil {
    namespace blueprint {
        template <typename PlaceholderParams>
        using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
            typename PlaceholderParams::field_type,
            PlaceholderParams
        >::preprocessed_data_type::common_data_type;

        template<typename PlaceholderParams>
        void commitment_scheme_replaces(
            const zk::snark::placeholder_info<PlaceholderParams> &placeholder_info,
            zk::snark::plonk_table_description<typename PlaceholderParams::field_type> desc,
            transpiler_replacements& replacements,
            const common_data_type<PlaceholderParams> &common_data,
            const typename PlaceholderParams::commitment_scheme_type& lpc_scheme,
            std::size_t permutation_size,
            std::size_t quotient_polys,
            std::size_t lookup_polys,
            bool use_lookups
        ){
            std::set<std::string> unique_points;
            std::vector<std::string> points;

            auto [z_points_indices, singles_strs, singles_map, poly_ids] = calculate_unique_points<PlaceholderParams, common_data_type<PlaceholderParams>>(
                placeholder_info,
                desc,
                common_data, permutation_size, quotient_polys, lookup_polys,
                "evm" // Generator mode
            );

            std::stringstream points_initializer;
            std::size_t i = 0;

            for(const auto& point: singles_strs){
                points_initializer << "\t\tresult[" << i << "] = " << point << ";" << std::endl;
                i++;
            }

            std::stringstream points_ids;
            for( const auto& point_id: z_points_indices){
                points_ids << std::hex << std::setw(2) << std::setfill('0') << point_id;
            }

            std::stringstream poly_ids_str;
            std::stringstream poly_points_num;
            for(i = 0; i < poly_ids.size(); i++){
                poly_points_num << std::hex << std::setw(4) << std::setfill('0') << poly_ids[i].size();
                for(std::size_t j = 0; j < poly_ids[i].size(); j++){
                    poly_ids_str << std::hex << std::setw(4) << std::setfill('0') << poly_ids[i][j] * 0x40;
                }
            }

            std::string eta_point_U;
            std::vector<typename PlaceholderParams::field_type::value_type> eta_points;
            for( const auto &it:common_data.commitment_scheme_data){
                for( std::size_t i = 0; i < it.second.size(); i++ )
                    eta_points.push_back(it.second[i]);
            }
            for( std::size_t i = 0; i < eta_points.size(); i++){
                eta_point_U += "\t\tresult = addmod(0x" +to_hex_string(eta_points[eta_points.size() - i - 1]) + ", mulmod(result, theta, modulus), modulus);\n";
            }

            std::vector<std::uint8_t> init_blob = {};
            nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<typename PlaceholderParams::transcript_hash_type> transcript(init_blob);
            transcript(common_data.vk.constraint_system_with_params_hash);
            transcript(common_data.vk.fixed_values_commitment);
            auto etha = transcript.template challenge<typename PlaceholderParams::field_type>();

            auto fri_params = lpc_scheme.get_commitment_params();
            replacements["$R$"] = to_string(fri_params.r);
            replacements["$LAMBDA$"] = to_string(fri_params.lambda);
            replacements["$D0_SIZE$"] = to_string(fri_params.D[0]->m);
            replacements["$D0_LOG$"] = to_string(log2(fri_params.D[0]->m));
            replacements["$D0_OMEGA$"] = to_string(fri_params.D[0]->get_domain_element(1));
            replacements["$MAX_DEGREE$"] = to_string(fri_params.max_degree);
            replacements["$UNIQUE_POINTS$"] = to_string(singles_strs.size());
            replacements["$DIFFERENT_POINTS$"] = to_string(singles_strs.size());
            replacements["$POINTS_IDS$"] = points_ids.str();
            replacements["$POLY_IDS$"] = poly_ids_str.str();
            replacements["$POLY_POINTS_NUM$"] = poly_points_num.str();
            replacements["$POINTS_INITIALIZATION$"] = points_initializer.str();
            replacements["$ETA$"] = to_string(etha);
            replacements["$ETA_POINT_U$"] = eta_point_U;
            replacements["$FIXED_BATCH_SIZE$"] = to_string(placeholder_info.batches_sizes[0]);
/*          if( fri_params.use_grinding){
                auto params = PlaceholderParams::commitment_scheme_type::fri_type::grinding_type::get_params();
                uint32_t mask_value = params.template get<uint32_t>("mask", 0);
                std::stringstream mask_value_hex;
                mask_value_hex << std::hex << std::showbase << std::setw(8) << std::setfill('0') << mask_value;
                replacements["$GRINDING_CHECK$"] = modular_commitment_grinding_check_template;
                replacements["$GRINDING_MASK$"] = mask_value_hex.str();
            } else {*/
                replacements["$GRINDING_CHECK$"] = "";
//            }
        }

        template<typename PlaceholderParams>
        std::string generate_commitment_scheme_code(
            const common_data_type<PlaceholderParams> &common_data,
            const typename PlaceholderParams::commitment_scheme_type::params_type& fri_params
        ){
            BOOST_ASSERT(fri_params.step_list.size() == fri_params.r);
            for(std::size_t i = 0; i < fri_params.step_list.size(); i++){
                BOOST_ASSERT(fri_params.step_list[i] == 1);
            }
            std::stringstream out;

            return out.str();
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__