//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_HPP
#define CRYPTO3_STREAM_HPP

namespace nil {
    namespace crypto3 {
        /*!
         * @defgroup stream Stream Ciphers
         * @brief In contrast to block ciphers, stream ciphers operate on a plaintext stream
         * instead of blocks. Thus encrypting data results in changing the internal state
         * of the cipher and encryption of plaintext with arbitrary length is possible in
         * one go (in byte amounts).
         *
         * @defgroup stream_algorithms Algorithms
         * @ingroup stream
         * @brief Algorithms are meant to provide decryption interface similar to STL algorithms' one.
         */
    }
}

#endif    // CRYPTO3_STREAM_HPP
