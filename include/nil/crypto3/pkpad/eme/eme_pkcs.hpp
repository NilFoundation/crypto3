//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_EME_PKCS1_HPP
#define CRYPTO3_EME_PKCS1_HPP

#include <nil/crypto3/pkpad/eme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                /*!
                 * @brief EME from PKCS #1 v1.5
                 */
                template<typename Scheme, typename Hash>
                class eme_pkcs1v15 : public eme<Scheme, Hash> {
                public:
                    template<typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                             typename InputIterator, typename OutputIterator>
                    OutputIterator pad(InputIterator first, InputIterator last, OutputIterator out,
                                       std::size_t key_length, UniformRandomBitGenerator rand,
                                       RandomNumberDistribution dist) {
                        std::ptrdiff_t distance = std::distance(first, last);

                        if (distance > maximum_input_size(key_length)) {
                            throw std::invalid_argument("PKCS1: Input is too large");
                        }

                        key_length /= 8;

                        secure_vector<uint8_t> out(key_length);

                        out[0] = 0x02;
                        rand.randomize(out.data() + 1, (key_length - distance - 2));

                        for (size_t j = 1; j != key_length - distance - 1; ++j) {
                            if (out[j] == 0) {
                                out[j] = rand.next_nonzero_byte();
                            }
                        }

                        buffer_insert(out, key_length - distance, in, distance);

                        return out;
                    }

                    template<typename InputIterator, typename OutputIterator>
                    OutputIterator unpad(InputIterator first, InputIterator last, OutputIterator out) {
                        std::ptrdiff_t distance = std::distance(first, last);

                        if (distance < 2) {
                            throw std::invalid_argument("");
                        }

                        ct::poison(in, distance);

                        uint8_t bad_input_m = 0;
                        uint8_t seen_zero_m = 0;
                        size_t delim_idx = 0;

                        bad_input_m |= ~ct::is_equal<uint8_t>(*first, 0);
                        bad_input_m |= ~ct::is_equal<uint8_t>(*(first + 1), 2);

                        for (size_t i = 2; i < distance; ++i) {
                            const uint8_t is_zero_m = ct::is_zero<uint8_t>(in[i]);

                            delim_idx += ct::select<uint8_t>(~seen_zero_m, 1, 0);

                            bad_input_m |= is_zero_m & ct::expand_mask<uint8_t>(i < 10);
                            seen_zero_m |= is_zero_m;
                        }

                        bad_input_m |= ~seen_zero_m;
                        bad_input_m |= ct::is_less<size_t>(delim_idx, 8);

                        ct::unpoison(in, distance);
                        ct::unpoison(bad_input_m);
                        ct::unpoison(delim_idx);

                        secure_vector<uint8_t> output(&in[delim_idx + 2], &in[distance]);
                        ct::cond_zero_mem(bad_input_m, output.data(), output.size());

                        return out;
                    }

                    virtual size_t maximum_input_size(std::size_t key_bits) const override {
                        if (key_bits / 8 > 10) {
                            return ((key_bits / 8) - 10);
                        } else {
                            return 0;
                        }
                    }
                };
            }    // namespace padding
        }        // namespace pubkey
    }    // namespace crypto3
}    // namespace nil

#endif
