//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CIPHERTEXT_STEALING_HPP
#define CRYPTO3_CIPHERTEXT_STEALING_HPP

#include <cstdlib>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                template<std::size_t Version, typename Cipher, typename Padding>
                struct ciphertext_stealing_mode {};

                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<0, Cipher, Padding> {};

                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<1, Cipher, Padding> {};

                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<2, Cipher, Padding> {};

                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<3, Cipher, Padding> {};

                template<std::size_t Version, typename Cipher, typename Padding>
                using cts = ciphertext_stealing_mode<Version, Cipher, Padding>;

                template<typename Cipher, typename Padding>
                using cts0 = ciphertext_stealing_mode<0, Cipher, Padding>;

                template<typename Cipher, typename Padding>
                using cts1 = ciphertext_stealing_mode<1, Cipher, Padding>;

                template<typename Cipher, typename Padding>
                using cts2 = ciphertext_stealing_mode<2, Cipher, Padding>;

                template<typename Cipher, typename Padding>
                using cts3 = ciphertext_stealing_mode<3, Cipher, Padding>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHERTEXT_STEALING_HPP
