//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_STATE_HPP
#define CRYPTO3_HASH_STATE_HPP

#include <array>
#include <iterator>

#include <nil/concept_container/basic_concept_container.hpp>

#include <nil/crypto3/hash/detail/pack.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @brief Hash state managing container
             *
             * Meets the requirements of HashStateContainer, ConceptContainer, SequenceContainer, Container
             *
             * @tparam Hasher
             * @tparam Endian
             * @tparam ValueBits
             * @tparam LengthBits
             */
            template<typename Hasher, typename Endian, std::size_t ValueBits, std::size_t LengthBits>
            struct hash_state : public basic_concept_container<typename Hasher::digest_type,
                                                         typename Hasher::template stream_processor<ValueBits>> {
                typedef Hasher hash_type;
                typedef typename basic_concept_container<typename Hasher::digest_type,
                                                   typename Hasher::template stream_processor<
                                                           ValueBits>>::container_type container_type;
            };
        }
    }
} // namespace nil

#endif // CRYPTO3_BLOCK_STREAM_PREPROCESSOR_HPP