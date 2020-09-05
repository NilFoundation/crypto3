//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_ALT_BN128_BASIC_POLICY_HPP
#define ALGEBRA_PAIRING_ALT_BN128_BASIC_POLICY_HPP

#include <nil/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            struct basic_policy<alt_bn128<ModulusBits, GeneratorBits>> {

                using number_type = alt_bn128<ModulusBits, GeneratorBits>::number_type;

                constexpr static const typename number_type ate_loop_count = number_type(0x19D797039BE763BA8);
                constexpr static const bool ate_is_loop_count_neg = false;
                constexpr static const typename number_type final_exponent = number_type(
                    0x2F4B6DC97020FDDADF107D20BC842D43BF6369B1FF6A1C71015F3F7BE2E1E30A73BB94FEC0DAF15466B2383A5D3EC3D15AD524D8F70C54EFEE1BD8C3B21377E563A09A1B705887E72ECEADDEA3790364A61F676BAAF977870E88D5C6C8FEF0781361E443AE77F5B63A2A2264487F2940A8B1DDB3D15062CD0FB2015DFC6668449AED3CC48A82D0D602D268C7DAAB6A41294C0CC4EBE5664568DFC50E1648A45A4A1E3A5195846A3ED011A337A02088EC80E0EBAE8755CFE107ACF3AAFB40494E406F804216BB10CF430B0F37856B42DB8DC5514724EE93DFB10826F0DD4A0364B9580291D2CD65664814FDE37CA80BB4EA44EACC5E641BBADF423F9A2CBF813B8D145DA90029BAEE7DDADDA71C7F3811C4105262945BBA1668C3BE69A3C230974D83561841D766F9C9D570BB7FBE04C7E8A6C3C760C0DE81DEF35692DA361102B6B9B2B918837FA97896E84ABB40A4EFB7E54523A486964B64CA86F120_cppui2790);

                constexpr static const typename number_type final_exponent_z = number_type(0x44E992B44A6909F1);
                constexpr static const typename number_type final_exponent_is_z_neg = false;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_ALT_BN128_BASIC_POLICY_HPP