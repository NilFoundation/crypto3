//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_ANSI_X942_PRF_HPP
#define CRYPTO3_KDF_ANSI_X942_PRF_HPP

#include <nil/crypto3/kdf/detail/prf_x942/prf_x942_functions.hpp>

#include <nil/crypto3/hash/sha1.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief PRF from ANSI X9.42.
             * @tparam Hash
             */
            template<typename Hash = hash::sha1>
            class x942_prf {
                typedef detail::prf_x942_functions<Hash> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;

                static void process() {
                    const OID kek_algo(m_key_wrap_oid);

                    secure_vector<uint8_t> h;
                    secure_vector<uint8_t> in;
                    size_t offset = 0;
                    uint32_t counter = 1;

                    in.reserve(salt_len + label_len);
                    in += std::make_pair(label, label_len);
                    in += std::make_pair(salt, salt_len);

                    while (offset != key_len && counter) {
                        hash->update(secret, secret_len);

                        hash->update(
                            der_encoder()
                                .start_cons(SEQUENCE)

                                .start_cons(SEQUENCE)
                                .encode(kek_algo)
                                .raw_bytes(encode_x942_int(counter))
                                .end_cons()

                                .encode_if(salt_len != 0,
                                           der_encoder().start_explicit(0).encode(in, OCTET_STRING).end_explicit())

                                .start_explicit(2)
                                .raw_bytes(encode_x942_int(static_cast<uint32_t>(8 * key_len)))
                                .end_explicit()

                                .end_cons()
                                .get_contents());

                        hash->final(h);
                        const size_t copied = std::min(h.size(), key_len - offset);
                        copy_mem(&key[offset], h.data(), copied);
                        offset += copied;

                        ++counter;
                    }

                    return offset;
                }
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif
