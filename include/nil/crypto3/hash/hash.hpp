//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_FUNCTION_BASE_CLASS_H_
#define CRYPTO3_HASH_FUNCTION_BASE_CLASS_H_

#include <nil/crypto3/utilities/buf_comp.hpp>

#include <string>
#include <memory>

namespace nil {
    namespace crypto3 {
        /*!
         * @defgroup hash Hash Functions & Checksums
         *
         * @brief Hash functions are one-way functions, which map data of arbitrary size to a
         * fixed output length. Most of the hash functions in crypto3 are designed to be
         * cryptographically secure, which means that it is computationally infeasible to
         * create a collision (finding two inputs with the same hash) or preimages (given a
         * hash output, generating an arbitrary input with the same hash). But note that
         * not all such hash functions meet their goals, in particular @ref nil::crypto3::hash::md4 "MD4" and @ref
         * nil::crypto3::hash::md5 "MD5" are trivially broken. However they are still included due to their wide
         * adoption in various protocols.
         *
         * Using a hash function is typically split into three stages: initialization,
         * update, and finalization (often referred to as a IUF interface). The
         * initialization stage is implicit: after creating a hash function object, it is
         * ready to process data. Then update is called one or more times. Calling update
         * several times is equivalent to calling it once with all of the arguments
         * concatenated. After completing a hash computation (eg using ``final``), the
         * internal state is reset to begin hashing a new message.
         */
        namespace hash {

        }

/**
* This class represents hash function (message digest) objects
*/
        class HashFunction : public buffered_computation {
        public:

            /**
            * Create an instance based on a name, or return null if the
            * algo/provider combination cannot be found. If provider is
            * empty then best available is chosen.
            */
            static std::unique_ptr<HashFunction> create(const std::string &algo_spec, const std::string &provider = "");

            /**
            * Create an instance based on a name
            * If provider is empty then best available is chosen.
            * @param algo_spec algorithm name
            * @param provider provider implementation to use
            * Throws Lookup_Error if not found.
            */
            static std::unique_ptr<HashFunction> create_or_throw(const std::string &algo_spec,
                                                                 const std::string &provider = "");

            /**
            * @return list of available providers for this algorithm, empty if not available
            * @param algo_spec algorithm name
            */
            static std::vector<std::string> providers(const std::string &algo_spec);

            /**
            * @return new object representing the same algorithm as *this
            */
            virtual HashFunction *clone() const = 0;

            /**
            * @return provider information about this implementation. Default is "base",
            * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
            */
            virtual std::string provider() const {
                return "core";
            }

            virtual ~HashFunction() = default;

            /**
            * Reset the state.
            */
            virtual void clear() = 0;

            /**
            * @return the hash function name
            */
            virtual std::string name() const = 0;

            /**
            * @return hash block size as defined for this algorithm
            */
            virtual size_t hash_block_size() const {
                return 0;
            }

            /**
            * Return a new hash object with the same state as *this. This
            * allows computing the hash of several messages with a common
            * prefix more efficiently than would otherwise be possible.
            *
            * This function should be called `clone` but that was already
            * used for the case of returning an uninitialized object.
            * @return new hash object
            */
            virtual std::unique_ptr<HashFunction> copy_state() const = 0;
        };
    }
}

#endif
