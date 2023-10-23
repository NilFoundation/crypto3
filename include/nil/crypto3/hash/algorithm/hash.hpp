//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_HPP
#define CRYPTO3_HASH_HPP

#ifdef __ZKLLVM__
#else
#include <nil/crypto3/hash/hash_value.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#endif

namespace nil {
    namespace crypto3 {

#ifdef __ZKLLVM__
        template <class HashType>
        typename HashType::block_type hash(typename HashType::block_type block0, typename HashType::block_type block1){
           return typename HashType::process()(block0, block1);
        }
#else
        /*!
         * @defgroup hashes Hash Functions & Checksums
         *
         * @brief Hash functions are one-way functions, which map data of arbitrary size to a
         * fixed output length. Most of the hashes functions in crypto3 are designed to be
         * cryptographically secure, which means that it is computationally infeasible to
         * create a collision (finding two inputs with the same hashes) or preimages (given a
         * hashes output, generating an arbitrary input with the same hashes). But note that
         * not all such hashes functions meet their goals, in particular @ref nil::crypto3::hashes::md4 "MD4" and @ref
         * nil::crypto3::hashes::md5 "MD5" are trivially broken. However they are still included due to their wide
         * adoption in various protocols.
         *
         * Using a hashes function is typically split into three stages: initialization,
         * update, and finalization (often referred to as a IUF interface). The
         * initialization stage is implicit: after creating a hashes function object, it is
         * ready to process data. Then update is called one or more times. Calling update
         * several times is equivalent to calling it once with all of the arguments
         * concatenated. After completing a hashes computation (eg using ``final``), the
         * internal state is reset to begin hashing a new message.
         *
         * @defgroup hash_algorithms Algorithms
         * @ingroup hashes
         * @brief Algorithms are meant to provide hashing interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename Hash, typename InputIterator, typename OutputIterator,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            hash(InputIterator first, InputIterator last, OutputIterator out) {

            typedef accumulator_set<Hash> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(first, last, std::move(out), HashAccumulator());
        }

        // For Posseidon. Refactor this later.
        template<typename Hash, typename InputIterator, typename OutputIterator,
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out) {
            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            while (first != last) {
                sponge.absorb(*first++);
            }
            *out = sponge.squeeze();
            ++out;
            return out;
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam HashAccumulator
         *
         * @param first
         * @param last
         * @param sh
         *
         * @return
         */
        template<typename Hash, typename InputIterator, typename HashAccumulator = accumulator_set<Hash>,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
                                HashAccumulator>::type
            hash(InputIterator first, InputIterator last, HashAccumulator &sh) {

            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(first, last, sh);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam HashAccumulator
         *
         * @param first
         * @param last
         *
         * @return
         */
        template<typename Hash, typename InputIterator, typename HashAccumulator = accumulator_set<Hash>,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        hashes::detail::range_hash_impl<hashes::detail::value_hash_impl<typename std::enable_if<
            boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value, HashAccumulator>::type>>
            hash(InputIterator first, InputIterator last) {


            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(first, last, HashAccumulator());
        }
        
        // For posseidon.
        template<typename Hash, typename InputIterator,
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value &&
                             nil::crypto3::detail::is_iterator<InputIterator>::value, bool> = true>
        typename Hash::digest_type hash(InputIterator first, InputIterator last) {

            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            while (first != last) {
                sponge.absorb(*first++);
            }
            return sponge.squeeze();
 
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         *
         * @return
         */
        template<typename Hash, typename SinglePassRange, typename OutputIterator,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            hash(const SinglePassRange &rng, OutputIterator out) {

            typedef accumulator_set<Hash> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(rng, std::move(out), HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam HashAccumulator
         *
         * @param rng
         * @param sh
         *
         * @return
         */
        template<typename Hash, typename SinglePassRange, typename HashAccumulator = accumulator_set<Hash>,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
                                HashAccumulator>::type
            hash(const SinglePassRange &rng, HashAccumulator &sh) {

            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(rng, sh);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam HashAccumulator
         *
         * @param r
         *
         * @return
         */
        template<typename Hash, typename SinglePassRange, typename HashAccumulator = accumulator_set<Hash>, 
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        hashes::detail::range_hash_impl<hashes::detail::value_hash_impl<HashAccumulator>>
            hash(const SinglePassRange &r) {

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(r, HashAccumulator());
        }

        // TODO: Use packing in the block_stream_processor in the future, now it will work well with 256 bit 
        // field elements which are used in posseidon. Also try to use concepts, not fix the posseidon class type.

        // This function is used for merkle tree, where multiple group elements are hashed together to create the parent element.
        template<typename Hash, typename GroupElementsContainer,
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value &&
                             std::is_same<typename Hash::digest_type, typename GroupElementsContainer::value_type>::value, bool> = true>
        typename Hash::digest_type hash(const GroupElementsContainer &r, const typename Hash::digest_type& initial_element) {

            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            sponge.absorb(initial_element);

            for (const auto& element: r) {
                sponge.absorb(element);
            }
            return sponge.squeeze();
        }

        // This function is used for merkle tree, where multiple group elements are hashed together to create the parent element.
        template<typename Hash, typename GroupElementsContainer,
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value &&
                             std::is_same<typename Hash::digest_type, typename GroupElementsContainer::value_type>::value, bool> = true>
        typename Hash::digest_type hash(const GroupElementsContainer &r) {

            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            for (const auto& element: r) {
                sponge.absorb(element);
            }
            return sponge.squeeze();
        }

        // This function is used for merkle tree to initially hash the original elements in the tree leaves.
        template<typename Hash, typename GroupElement, 
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value && 
                             std::is_same<typename Hash::digest_type, GroupElement>::value, bool> = true>
        typename Hash::digest_type hash(const GroupElement &element, const typename Hash::digest_type& initial_element) {

            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            sponge.absorb(initial_element);
            sponge.absorb(element);

            return sponge.squeeze();
        }

        template<typename Hash, typename GroupElement, 
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value && 
                             std::is_same<typename Hash::digest_type, GroupElement>::value, bool> = true>
        typename Hash::digest_type hash(const GroupElement &element) {

            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            sponge.absorb(element);

            return sponge.squeeze();
        }

        // This function is used for hashing containers of integral values using Posseidon hash. 
        // Usually this will pack a vector of 8-bit integers into a 255 bit group element, which means the last 
        // 7 bits will not be used in the current implementation. Also group element multiplications are pretty slow. 
        template<typename Hash, typename IntegralContainer,
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value &&
                             std::is_integral<typename IntegralContainer::value_type>::value, bool> = true>
        typename Hash::digest_type absorb(hashes::detail::poseidon_sponge_construction<typename Hash::policy_type>& sponge, 
                                          const IntegralContainer &r) {
            typename Hash::digest_type next_element = Hash::digest_type::zero();
            std::size_t bits_left = Hash::word_bits;
            
            std::size_t input_word_size = CHAR_BIT * sizeof(typename IntegralContainer::value_type);

            // At least 1 input word must fit in a single group element.
            // Normally group element is 255 or 256 bits, while input word size is 8 or 32 or 64 bits.
            assert(input_word_size <= Hash::word_bits); 

            for (const auto& word: r) {
                if (bits_left < input_word_size) {
                    sponge.absorb(next_element);
                    next_element = Hash::digest_type::zero();
                    bits_left = Hash::word_bits;
                }
                next_element *= 1 << input_word_size; 
                next_element += word;
                bits_left -= input_word_size;
            }

            if (bits_left != Hash::word_bits) {
                sponge.absorb(next_element);
            }

            return sponge.squeeze();
        }

        template<typename Hash, typename IntegralContainer, 
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value && 
                             std::is_integral<typename IntegralContainer::value_type>::value, bool> = true>
        typename Hash::digest_type hash(const IntegralContainer &r, const typename Hash::digest_type& initial_element) {
            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;

            sponge.absorb(initial_element);
            return absorb<Hash>(sponge, r);
        }

        template<typename Hash, typename IntegralContainer, 
            std::enable_if_t<crypto3::hashes::is_poseidon<Hash>::value && 
                             std::is_integral<typename IntegralContainer::value_type>::value, bool> = true>
        typename Hash::digest_type hash(const IntegralContainer &r) {
            hashes::detail::poseidon_sponge_construction<typename Hash::policy_type> sponge;
            return absorb<Hash>(sponge, r);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         *
         * @return
         */
        template<typename Hash, typename T, typename OutputIterator,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            hash(std::initializer_list<T> list, OutputIterator out) {

            typedef accumulator_set<Hash> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(list, std::move(out), HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam HashAccumulator
         *
         * @param rng
         * @param sh
         *
         * @return
         */
        template<typename Hash, typename T, typename HashAccumulator = accumulator_set<Hash>,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
                                HashAccumulator>::type
            hash(std::initializer_list<T> rng, HashAccumulator &sh) {

            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(rng, sh);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam HashAccumulator
         *
         * @param r
         *
         * @return
         */
        template<typename Hash, typename T, typename HashAccumulator = accumulator_set<Hash>,
            std::enable_if_t<!crypto3::hashes::is_poseidon<Hash>::value, bool> = true>
        hashes::detail::range_hash_impl<hashes::detail::value_hash_impl<HashAccumulator>>
            hash(std::initializer_list<T> r) {

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(r, HashAccumulator());
        }
#endif
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HPP
