//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_MNT6_BASIC_POLICY_HPP
#define ALGEBRA_PAIRING_MNT6_BASIC_POLICY_HPP

#include <nil/algebra/curves/mnt6.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            struct basic_policy <mnt6<ModulusBits, GeneratorBits>>{

                using number_type = mnt6<ModulusBits, GeneratorBits>::number_type;

                constexpr static const typename number_type ate_loop_count = number_type(0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149);
                constexpr static const bool ate_is_loop_count_neg = true;
                constexpr static const typename number_type final_exponent = number_type(
                    0x2D9F068E10293574745C62CB0EE7CF1D27F98BA7E8F16BB1CB498038B1B0B4D7EA28C42575093726D5E360818F2DD5B39038CFF6405359561DD2F2F0627F9264724E069A7198C17873F7F54D8C7CE3D5DAED1AC5E87C26C03B1F481813BB668B6FEDC7C2AAA83936D8BC842F74C66E7A13921F7D91474B3981D3A3B3B40537720C84FE27E3E90BB29DB12DFFE17A286C150EF5071B3087765F9454046ECBDD3B014FF91A1C18D55DB868E841DBF82BCCEFB4233833BD800000000_cppui1490
                );

                constexpr static const typename number_type final_exponent_last_chunk_abs_of_w0 = number_type(0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149); // same as ate_loop_count?
                constexpr static const typename number_type final_exponent_last_chunk_is_w0_neg = true;
                constexpr static const typename number_type final_exponent_last_chunk_w1 = number_type(0x1);

            };
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT6_BASIC_POLICY_HPP