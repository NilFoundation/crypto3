//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_XMSS_PARAMETERS_HPP
#define CRYPTO3_PUBKEY_XMSS_PARAMETERS_HPP

#include <nil/crypto3/pubkey/xmss/xmss_wots_parameters.hpp>

#include <string>

namespace nil {
    namespace crypto3 {

        /**
         * Descibes a signature method for XMSS, as defined in:
         * [1] XMSS: Extended Hash-Based Signatures,
         *     draft-itrf-cfrg-xmss-hash-based-signatures-06
         *     Release: July 2016.
         *     https://datatracker.ietf.org/doc/
         *     draft-irtf-cfrg-xmss-hash-based-signatures/?include_text=1
         **/
        class CRYPTO3_PUBLIC_API(

            2,
            0) XMSS_Parameters {
        public:
            enum xmss_algorithm_t {
                XMSS_SHA2_256_W16_H10 = 0x01000001,
                XMSS_SHA2_256_W16_H16 = 0x02000002,
                XMSS_SHA2_256_W16_H20 = 0x03000003,
                XMSS_SHA2_512_W16_H10 = 0x04000004,
                XMSS_SHA2_512_W16_H16 = 0x05000005,
                XMSS_SHA2_512_W16_H20 = 0x06000006,
                XMSS_SHAKE128_W16_H10 = 0x07000007,
                XMSS_SHAKE128_W16_H16 = 0x08000008,
                XMSS_SHAKE128_W16_H20 = 0x09000009,
                XMSS_SHAKE256_W16_H10 = 0x0a00000a,
                XMSS_SHAKE256_W16_H16 = 0x0b00000b,
                XMSS_SHAKE256_W16_H20 = 0x0c00000c
            };

            static xmss_algorithm_t xmss_id_from_string(const std::string &algo_name);

            XMSS_Parameters(const std::string &algo_name);

            XMSS_Parameters(xmss_algorithm_t oid);

            /**
             * @return XMSS registry name for the chosen parameter set.
             **/
            const std::string &name() const {
                return m_name;
            }

            const std::string &hash_function_name() const {
                return m_hash_name;
            }

            /**
             * Retrieves the uniform length of a message, and the size of
             * each node. This correlates to XMSS parameter "n" defined
             * in [1].
             *
             * @return element length in bytes.
             **/
            size_t element_size() const {
                return m_element_size;
            }

            /**
             * @returns The height (number of levels - 1) of the tree
             **/
            size_t tree_height() const {
                return m_tree_height;
            }

            /**
             * The Winternitz parameter.
             *
             * @return numeric base used for internal representation of
             *         data.
             **/
            size_t wots_parameter() const {
                return m_w;
            }

            size_t len() const {
                return m_len;
            }

            xmss_algorithm_t oid() const {
                return m_oid;
            }

            XMSS_WOTS_Parameters::ots_algorithm_t ots_oid() const {
                return m_wots_oid;
            }

            /**
             * Returns the estimated pre-quantum security level of
             * the chosen algorithm.
             **/
            size_t estimated_strength() const {
                return m_strength;
            }

            bool operator==(const XMSS_Parameters &p) const {
                return m_oid == p.m_oid;
            }

        private:
            xmss_algorithm_t m_oid;
            XMSS_WOTS_Parameters::ots_algorithm_t m_wots_oid;
            std::string m_name;
            std::string m_hash_name;
            size_t m_element_size;
            size_t m_tree_height;
            size_t m_w;
            size_t m_len;
            size_t m_strength;
        };

        XMSS_Parameters::xmss_algorithm_t XMSS_Parameters::xmss_id_from_string(const std::string &param_set) {
            if (param_set == "XMSS_SHA2-256_W16_H10") {
                return XMSS_SHA2_256_W16_H10;
            }
            if (param_set == "XMSS_SHA2-256_W16_H16") {
                return XMSS_SHA2_256_W16_H16;
            }
            if (param_set == "XMSS_SHA2-256_W16_H20") {
                return XMSS_SHA2_256_W16_H20;
            }
            if (param_set == "XMSS_SHA2-512_W16_H10") {
                return XMSS_SHA2_512_W16_H10;
            }
            if (param_set == "XMSS_SHA2-512_W16_H16") {
                return XMSS_SHA2_512_W16_H16;
            }
            if (param_set == "XMSS_SHA2-512_W16_H20") {
                return XMSS_SHA2_512_W16_H20;
            }
            if (param_set == "XMSS_SHAKE128_W16_H10") {
                return XMSS_SHAKE128_W16_H10;
            }
            if (param_set == "XMSS_SHAKE128_W16_H16") {
                return XMSS_SHAKE128_W16_H16;
            }
            if (param_set == "XMSS_SHAKE128_W16_H20") {
                return XMSS_SHAKE128_W16_H20;
            }
            if (param_set == "XMSS_SHAKE256_W16_H10") {
                return XMSS_SHAKE256_W16_H10;
            }
            if (param_set == "XMSS_SHAKE256_W16_H16") {
                return XMSS_SHAKE256_W16_H16;
            }
            if (param_set == "XMSS_SHAKE256_W16_H20") {
                return XMSS_SHAKE256_W16_H20;
            }
            throw Lookup_Error("Unknown XMSS algorithm param '" + param_set + "'");
        }

        XMSS_Parameters::XMSS_Parameters(const std::string &param_set) :
            XMSS_Parameters(XMSS_Parameters::xmss_id_from_string(param_set)) {
        }

        XMSS_Parameters::XMSS_Parameters(xmss_algorithm_t oid) : m_oid(oid) {
            switch (oid) {
                case XMSS_SHA2_256_W16_H10:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_tree_height = 10;
                    m_name = "XMSS_SHA2-256_W16_H10";
                    m_hash_name = "SHA-256";
                    m_strength = 256;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256_W16;
                    break;
                case XMSS_SHA2_256_W16_H16:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_tree_height = 16;
                    m_name = "XMSS_SHA2-256_W16_H16";
                    m_hash_name = "SHA-256";
                    m_strength = 256;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256_W16;
                    break;
                case XMSS_SHA2_256_W16_H20:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_tree_height = 20;
                    m_name = "XMSS_SHA2-256_W16_H20";
                    m_hash_name = "SHA-256";
                    m_strength = 256;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256_W16;
                    break;
                case XMSS_SHA2_512_W16_H10:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_tree_height = 10;
                    m_name = "XMSS_SHA2-512_W16_H10";
                    m_hash_name = "SHA-512";
                    m_strength = 512;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512_W16;
                    break;
                case XMSS_SHA2_512_W16_H16:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_tree_height = 16;
                    m_name = "XMSS_SHA2-512_W16_H16";
                    m_hash_name = "SHA-512";
                    m_strength = 512;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512_W16;
                    break;
                case XMSS_SHA2_512_W16_H20:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_tree_height = 20;
                    m_name = "XMSS_SHA2-512_W16_H20";
                    m_hash_name = "SHA-512";
                    m_strength = 512;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512_W16;
                    break;
                case XMSS_SHAKE128_W16_H10:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_tree_height = 10;
                    m_name = "XMSS_SHAKE128_W16_H10";
                    m_hash_name = "SHAKE-128(256)";
                    m_strength = 256;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE128_W16;
                    break;
                case XMSS_SHAKE128_W16_H16:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_tree_height = 16;
                    m_name = "XMSS_SHAKE128_W16_H16";
                    m_hash_name = "SHAKE-128(256)";
                    m_strength = 256;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE128_W16;
                    break;
                case XMSS_SHAKE128_W16_H20:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_tree_height = 20;
                    m_name = "XMSS_SHAKE128_W16_H20";
                    m_hash_name = "SHAKE-128(256)";
                    m_strength = 256;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE128_W16;
                    break;
                case XMSS_SHAKE256_W16_H10:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_tree_height = 10;
                    m_name = "XMSS_SHAKE256_W16_H10";
                    m_hash_name = "SHAKE-256(512)";
                    m_strength = 512;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE256_W16;
                    break;
                case XMSS_SHAKE256_W16_H16:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_tree_height = 16;
                    m_name = "XMSS_SHAKE256_W16_H16";
                    m_hash_name = "SHAKE-256(512)";
                    m_strength = 512;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE256_W16;
                    break;
                case XMSS_SHAKE256_W16_H20:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_tree_height = 20;
                    m_name = "XMSS_SHAKE256_W16_H20";
                    m_hash_name = "SHAKE-256(512)";
                    m_strength = 512;
                    m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE256_W16;
                    break;
                default:
                    throw Unsupported_Argument("Algorithm id does not match any XMSS algorithm id.");
                    break;
            }
        }
    }    // namespace crypto3
}    // namespace nil

#endif
