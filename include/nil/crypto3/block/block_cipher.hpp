//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHER_H_
#define CRYPTO3_BLOCK_CIPHER_H_

#include <string>
#include <memory>

#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/throw_exception.hpp>

#include <nil/crypto3/utilities/symmetric_algorithm.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @defgroup block Block Ciphers
             *
             * @brief Block ciphers are a n-bit permutation for some small ```n```,
             * typically 64 or 128 bits. It is a cryptographic primitive used
             * to generate higher level operations such as authenticated encryption.
             */
            template<typename Cipher, typename Mode, typename Padding>
            struct cipher : public Mode::template bind<Cipher, Padding>::type {
                typedef std::size_t size_type;

                typedef Cipher cipher_type;
                typedef Mode mode_type;
                typedef Padding padding_strategy;
            };

            class old_block_cipher {
            public:
                virtual std::size_t block_size() const = 0;
            };

            template<size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1>
            class fixed_block_cipher : public old_block_cipher {
            public:
                static const std::size_t block_size_value = BS;
                static const std::size_t key_length_min = KMIN;
                static const std::size_t key_length_max = KMAX;
                static const std::size_t key_modulus = KMOD;

                virtual std::size_t block_size() const override {
                    return block_size_value;
                }
            };
        }

/**
* This class represents a block cipher object.
*/
        class BlockCipher : public symmetric_algorithm {
        public:

            /**
            * Create an instance based on a name
            * If provider is empty then best available is chosen.
            * @param algo_spec algorithm name
            * @param provider provider implementation to choose
            * @return a null pointer if the algo/provider combination cannot be found
            */
            static std::unique_ptr<BlockCipher> create(const std::string &algo_spec, const std::string &provider = "");

            /**
            * Create an instance based on a name, or throw if the
            * algo/provider combination cannot be found. If provider is
            * empty then best available is chosen.
            */
            static std::unique_ptr<BlockCipher> create_or_throw(const std::string &algo_spec,
                                                                const std::string &provider = "");

            /**
            * @return list of available providers for this algorithm, empty if not available
            * @param algo_spec algorithm name
            */
            static std::vector<std::string> providers(const std::string &algo_spec);

            /**
            * @return block size of this algorithm
            */
            virtual size_t block_size() const = 0;

            /**
            * @return native parallelism of this cipher in blocks
            */
            virtual size_t parallelism() const {
                return 1;
            }

            /**
            * @return prefererred parallelism of this cipher in bytes
            */
            size_t parallel_bytes() const {
                return parallelism() * block_size() * CRYPTO3_BLOCK_CIPHER_PAR_MULT;
            }

            /**
            * @return provider information about this implementation. Default is "base",
            * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
            */
            virtual std::string provider() const {
                return "core";
            }

            /**
            * Encrypt a block.
            * @param in The plaintext block to be encrypted as a byte array.
            * Must be of length block_size().
            * @param out The byte array designated to hold the encrypted block.
            * Must be of length block_size().
            */
            void encrypt(const uint8_t in[], uint8_t out[]) const {
                encrypt_n(in, out, 1);
            }

            /**
            * Decrypt a block.
            * @param in The ciphertext block to be decypted as a byte array.
            * Must be of length block_size().
            * @param out The byte array designated to hold the decrypted block.
            * Must be of length block_size().
            */
            void decrypt(const uint8_t in[], uint8_t out[]) const {
                decrypt_n(in, out, 1);
            }

            /**
            * Encrypt a block.
            * @param block the plaintext block to be encrypted
            * Must be of length block_size(). Will hold the result when the function
            * has finished.
            */
            void encrypt(uint8_t block[]) const {
                encrypt_n(block, block, 1);
            }

            /**
            * Decrypt a block.
            * @param block the ciphertext block to be decrypted
            * Must be of length block_size(). Will hold the result when the function
            * has finished.
            */
            void decrypt(uint8_t block[]) const {
                decrypt_n(block, block, 1);
            }

            /**
            * Encrypt one or more blocks
            * @param block the input/output buffer (multiple of block_size())
            */
            template<typename Alloc>
            void encrypt(std::vector<uint8_t, Alloc> &block) const {
                return encrypt_n(block.data(), block.data(), block.size() / block_size());
            }

            /**
            * Decrypt one or more blocks
            * @param block the input/output buffer (multiple of block_size())
            */
            template<typename Alloc>
            void decrypt(std::vector<uint8_t, Alloc> &block) const {
                return decrypt_n(block.data(), block.data(), block.size() / block_size());
            }

            /**
            * Encrypt one or more blocks
            * @param in the input buffer (multiple of block_size())
            * @param out the output buffer (same size as in)
            */
            template<typename Alloc, typename Alloc2>
            void encrypt(const std::vector<uint8_t, Alloc> &in, std::vector<uint8_t, Alloc2> &out) const {
                return encrypt_n(in.data(), out.data(), in.size() / block_size());
            }

            /**
            * Decrypt one or more blocks
            * @param in the input buffer (multiple of block_size())
            * @param out the output buffer (same size as in)
            */
            template<typename Alloc, typename Alloc2>
            void decrypt(const std::vector<uint8_t, Alloc> &in, std::vector<uint8_t, Alloc2> &out) const {
                return decrypt_n(in.data(), out.data(), in.size() / block_size());
            }

            /**
            * Encrypt one or more blocks
            * @param in the input buffer (multiple of block_size())
            * @param out the output buffer (same size as in)
            * @param blocks the number of blocks to process
            */
            virtual void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const = 0;

            /**
            * Decrypt one or more blocks
            * @param in the input buffer (multiple of block_size())
            * @param out the output buffer (same size as in)
            * @param blocks the number of blocks to process
            */
            virtual void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const = 0;

            virtual void encrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const {
                const size_t BS = block_size();
                xor_buf(data, mask, blocks * BS);
                encrypt_n(data, data, blocks);
                xor_buf(data, mask, blocks * BS);
            }

            virtual void decrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const {
                const size_t BS = block_size();
                xor_buf(data, mask, blocks * BS);
                decrypt_n(data, data, blocks);
                xor_buf(data, mask, blocks * BS);
            }

            /**
            * @return new object representing the same algorithm as *this
            */
            virtual BlockCipher *clone() const = 0;

            virtual ~BlockCipher() = default;
        };

/**
* Represents a block cipher with a single fixed block size
*/
        template<size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1>
        class Block_Cipher_Fixed_Params : public BlockCipher {
        public:
            enum {
                BLOCK_SIZE = BS
            };

            size_t block_size() const override {
                return BS;
            }

            // override to take advantage of compile time constant block size
            void encrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const override {
                xor_buf(data, mask, blocks * BS);
                encrypt_n(data, data, blocks);
                xor_buf(data, mask, blocks * BS);
            }

            void decrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const override {
                xor_buf(data, mask, blocks * BS);
                decrypt_n(data, data, blocks);
                xor_buf(data, mask, blocks * BS);
            }

            key_length_spec_t key_spec() const override {
                return key_length_spec_t(KMIN, KMAX, KMOD);
            }
        };
    }
}

#endif
