//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SHA3_FUNCTIONS_HPP
#define CRYPTO3_SHA3_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/sha3_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct sha3_functions : public sha3_policy<DigestBits> {
                    typedef sha3_policy<DigestBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    static inline void permute(word_type A[25]) {
                        for (typename policy_type::round_constants_type::value_type c :
                                policy_type::round_constants) {
                            const word_type C0 = A[0] ^A[5] ^A[10] ^A[15] ^A[20];
                            const word_type C1 = A[1] ^A[6] ^A[11] ^A[16] ^A[21];
                            const word_type C2 = A[2] ^A[7] ^A[12] ^A[17] ^A[22];
                            const word_type C3 = A[3] ^A[8] ^A[13] ^A[18] ^A[23];
                            const word_type C4 = A[4] ^A[9] ^A[14] ^A[19] ^A[24];

                            const word_type D0 = policy_type::template rotl<1>(C0) ^C3;
                            const word_type D1 = policy_type::template rotl<1>(C1) ^C4;
                            const word_type D2 = policy_type::template rotl<1>(C2) ^C0;
                            const word_type D3 = policy_type::template rotl<1>(C3) ^C1;
                            const word_type D4 = policy_type::template rotl<1>(C4) ^C2;

                            const word_type B00 = A[0] ^D1;
                            const word_type B10 = policy_type::template rotl<1>(A[1] ^ D2);
                            const word_type B20 = policy_type::template rotl<62>(A[2] ^ D3);
                            const word_type B05 = policy_type::template rotl<28>(A[3] ^ D4);
                            const word_type B15 = policy_type::template rotl<27>(A[4] ^ D0);
                            const word_type B16 = policy_type::template rotl<36>(A[5] ^ D1);
                            const word_type B01 = policy_type::template rotl<44>(A[6] ^ D2);
                            const word_type B11 = policy_type::template rotl<6>(A[7] ^ D3);
                            const word_type B21 = policy_type::template rotl<55>(A[8] ^ D4);
                            const word_type B06 = policy_type::template rotl<20>(A[9] ^ D0);
                            const word_type B07 = policy_type::template rotl<3>(A[10] ^ D1);
                            const word_type B17 = policy_type::template rotl<10>(A[11] ^ D2);
                            const word_type B02 = policy_type::template rotl<43>(A[12] ^ D3);
                            const word_type B12 = policy_type::template rotl<25>(A[13] ^ D4);
                            const word_type B22 = policy_type::template rotl<39>(A[14] ^ D0);
                            const word_type B23 = policy_type::template rotl<41>(A[15] ^ D1);
                            const word_type B08 = policy_type::template rotl<45>(A[16] ^ D2);
                            const word_type B18 = policy_type::template rotl<15>(A[17] ^ D3);
                            const word_type B03 = policy_type::template rotl<21>(A[18] ^ D4);
                            const word_type B13 = policy_type::template rotl<8>(A[19] ^ D0);
                            const word_type B14 = policy_type::template rotl<18>(A[20] ^ D1);
                            const word_type B24 = policy_type::template rotl<2>(A[21] ^ D2);
                            const word_type B09 = policy_type::template rotl<61>(A[22] ^ D3);
                            const word_type B19 = policy_type::template rotl<56>(A[23] ^ D4);
                            const word_type B04 = policy_type::template rotl<14>(A[24] ^ D0);

                            A[0] = B00 ^ (~B01 & B02);
                            A[1] = B01 ^ (~B02 & B03);
                            A[2] = B02 ^ (~B03 & B04);
                            A[3] = B03 ^ (~B04 & B00);
                            A[4] = B04 ^ (~B00 & B01);
                            A[5] = B05 ^ (~B06 & B07);
                            A[6] = B06 ^ (~B07 & B08);
                            A[7] = B07 ^ (~B08 & B09);
                            A[8] = B08 ^ (~B09 & B05);
                            A[9] = B09 ^ (~B05 & B06);
                            A[10] = B10 ^ (~B11 & B12);
                            A[11] = B11 ^ (~B12 & B13);
                            A[12] = B12 ^ (~B13 & B14);
                            A[13] = B13 ^ (~B14 & B10);
                            A[14] = B14 ^ (~B10 & B11);
                            A[15] = B15 ^ (~B16 & B17);
                            A[16] = B16 ^ (~B17 & B18);
                            A[17] = B17 ^ (~B18 & B19);
                            A[18] = B18 ^ (~B19 & B15);
                            A[19] = B19 ^ (~B15 & B16);
                            A[20] = B20 ^ (~B21 & B22);
                            A[21] = B21 ^ (~B22 & B23);
                            A[22] = B22 ^ (~B23 & B24);
                            A[23] = B23 ^ (~B24 & B20);
                            A[24] = B24 ^ (~B20 & B21);

                            A[0] ^= c;
                        }
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_SHA3_FUNCTIONS_HPP
