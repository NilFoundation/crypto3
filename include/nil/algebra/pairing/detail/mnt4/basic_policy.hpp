//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_MNT4_BASIC_POLICY_HPP
#define ALGEBRA_PAIRING_MNT4_BASIC_POLICY_HPP

#include <nil/algebra/curves/mnt4.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            struct basic_policy<mnt4<ModulusBits, GeneratorBits>> {

                using number_type = mnt4<ModulusBits, GeneratorBits>::number_type;

                constexpr static const typename number_type ate_loop_count =
                    number_type(0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149);
                constexpr static const bool ate_is_loop_count_neg = false;
                constexpr static const typename number_type final_exponent = number_type(
                    0x343C7AC3174C87A1EFE216B37AFB6D3035ACCA5A07B2394F42E0029264C0324A95E87DCB6C97234CBA7385B8D20FEA4E85074066818687634E61F58B68EA590B11CEE431BE8348DEB351384D8485E987A57004BB9A1E7A6036C7A5801F55AC8E065E41B012422619E7E69541C5980000_cppui894);

                constexpr static const typename number_type final_exponent_last_chunk_abs_of_w0 =
                    number_type(0x1EEF5546609756BEC2A33F0DC9A1B671660001_cppui149);
                constexpr static const typename number_type final_exponent_last_chunk_is_w0_neg = false;
                constexpr static const typename number_type final_exponent_last_chunk_w1 = number_type(0x1);
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    //