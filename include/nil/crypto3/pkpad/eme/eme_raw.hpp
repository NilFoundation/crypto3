//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_EME_RAW_HPP
#define CRYPTO3_EME_RAW_HPP

#include <nil/crypto3/pkpad/eme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme, typename Hash>
                class eme_raw : public eme<Scheme, Hash> {
                public:
                    virtual size_t maximum_input_size(std::size_t key_bits) const override {
                        return key_bits / 8;
                    }

                    template<typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                             typename InputIterator, typename OutputIterator>
                    OutputIterator pad(InputIterator first, InputIterator last, OutputIterator out,
                                       std::size_t key_length,
                                       UniformRandomBitGenerator rand = UniformRandomBitGenerator()) {
                        return std::move(first, last, out);
                    }

                    template<typename InputIterator, typename OutputIterator>
                    OutputIterator unpad(InputIterator first, InputIterator last, OutputIterator out) {
                        return ct::strip_leading_zeros(first, static_cast<size_t>(std::distance(first, last)));
                    }
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
