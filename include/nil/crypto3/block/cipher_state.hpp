//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CIPHER_STATE_PREPROCESSOR_HPP
#define CRYPTO3_CIPHER_STATE_PREPROCESSOR_HPP

#include <nil/concept_container/cached_concept_container.hpp>

#include <nil/crypto3/block/cipher_state_preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Cipher state managing container
             *
             * Meets the requirements of CipherStateContainer, ConceptContainer, SequenceContainer, Container
             *
             * @tparam Mode Cipher state preprocessing mode type (e.g. isomorphic_encryption_mode<aes128>)
             * @tparam Endian
             * @tparam ValueBits
             * @tparam LengthBits
             */
            template<typename Mode, typename Endian, std::size_t ValueBits, std::size_t LengthBits> struct cipher_state
                    : public cached_concept_container<Mode, cipher_state_preprocessor < Mode, Endian, ValueBits,
                                                      LengthBits>> {

        };
    }
}
}

#endif //CRYPTO3_CIPHER_STATE_PREPROCESSOR_HPP
