#ifndef CRYPTO3_PUBKEY_XMSS_WOTS_PARAMETERS_HPP
#define CRYPTO3_PUBKEY_XMSS_WOTS_PARAMETERS_HPP

#include <map>
#include <string>

#include <nil/crypto3/pubkey/xmss/xmss_tools.hpp>
#include <nil/crypto3/utilities/secmem.hpp>

namespace nil {
    namespace crypto3 {

        /**
         * Descibes a signature method for XMSS Winternitz One Time Signatures,
         * as defined in:
         * [1] XMSS: Extended Hash-Based Signatures,
         *     draft-itrf-cfrg-xmss-hash-based-signatures-06
         *     Release: July 2016.
         *     https://datatracker.ietf.org/doc/
         *     draft-irtf-cfrg-xmss-hash-based-signatures/?include_text=1
         **/
        class XMSS_WOTS_Parameters final {
        public:
            enum ots_algorithm_t {
                WOTSP_SHA2_256_W16 = 0x01000001,
                WOTSP_SHA2_512_W16 = 0x02000002,
                WOTSP_SHAKE128_W16 = 0x03000003,
                WOTSP_SHAKE256_W16 = 0x04000004
            };

            XMSS_WOTS_Parameters(const std::string &algo_name);

            XMSS_WOTS_Parameters(ots_algorithm_t ots_spec);

            static ots_algorithm_t xmss_wots_id_from_string(const std::string &param_set);

            /**
             * Algorithm 1: convert input string to base.
             *
             * @param msg Input string (referred to as X in [1]).
             * @param out_size size of message in base w.
             *
             * @return Input string converted to the given base.
             **/
            secure_vector<uint8_t> base_w(const secure_vector<uint8_t> &msg, size_t out_size) const;

            secure_vector<uint8_t> base_w(size_t value) const;

            void append_checksum(secure_vector<uint8_t> &data);

            /**
             * @return XMSS WOTS registry name for the chosen parameter set.
             **/
            const std::string &name() const {
                return m_name;
            }

            /**
             * @return Botan name for the hash function used.
             **/
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

            size_t len_1() const {
                return m_len_1;
            }

            size_t len_2() const {
                return m_len_2;
            }

            size_t lg_w() const {
                return m_lg_w;
            }

            ots_algorithm_t oid() const {
                return m_oid;
            }

            size_t estimated_strength() const {
                return m_strength;
            }

            bool operator==(const XMSS_WOTS_Parameters &p) const {
                return m_oid == p.m_oid;
            }

        private:
            static const std::map<std::string, ots_algorithm_t> m_oid_name_lut;
            ots_algorithm_t m_oid;
            std::string m_name;
            std::string m_hash_name;
            size_t m_element_size;
            size_t m_w;
            size_t m_len_1;
            size_t m_len_2;
            size_t m_len;
            size_t m_strength;
            uint8_t m_lg_w;
        };

        XMSS_WOTS_Parameters::ots_algorithm_t
            XMSS_WOTS_Parameters::xmss_wots_id_from_string(const std::string &param_set) {
            if (param_set == "WOTSP_SHA2-256_W16") {
                return WOTSP_SHA2_256_W16;
            }
            if (param_set == "WOTSP_SHA2-512_W16") {
                return WOTSP_SHA2_512_W16;
            }
            if (param_set == "WOTSP_SHAKE128_W16") {
                return WOTSP_SHAKE128_W16;
            }
            if (param_set == "WOTSP_SHAKE256_W16") {
                return WOTSP_SHAKE256_W16;
            }
            throw std::invalid_argument("Unknown XMSS-WOTS algorithm param '" + param_set + "'");
        }

        XMSS_WOTS_Parameters::XMSS_WOTS_Parameters(const std::string &param_set) :
            XMSS_WOTS_Parameters(xmss_wots_id_from_string(param_set)) {
        }

        XMSS_WOTS_Parameters::XMSS_WOTS_Parameters(ots_algorithm_t oid) : m_oid(oid) {
            switch (oid) {
                case WOTSP_SHA2_256_W16:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_name = "WOTSP_SHA2-256_W16";
                    m_hash_name = "SHA-256";
                    m_strength = 256;
                    break;
                case WOTSP_SHA2_512_W16:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_name = "WOTSP_SHA2-512_W16";
                    m_hash_name = "SHA-512";
                    m_strength = 512;
                    break;
                case WOTSP_SHAKE128_W16:
                    m_element_size = 32;
                    m_w = 16;
                    m_len = 67;
                    m_name = "WOTSP_SHAKE128_W16";
                    m_hash_name = "SHAKE-128(256)";
                    m_strength = 256;
                    break;
                case WOTSP_SHAKE256_W16:
                    m_element_size = 64;
                    m_w = 16;
                    m_len = 131;
                    m_name = "WOTSP_SHAKE256_W16";
                    m_hash_name = "SHAKE-256(512)";
                    m_strength = 512;
                    break;
                default:
                    throw Unsupported_Argument("Algorithm id does not match any XMSS WOTS algorithm id.");
                    break;
            }

            m_w == 16 ? m_lg_w = 4 : m_lg_w = 2;
            m_len_1 = static_cast<size_t>(std::ceil((8 * element_size()) / m_lg_w));
            m_len_2 = static_cast<size_t>(floor(log2(m_len_1 * (wots_parameter() - 1)) / m_lg_w) + 1);
            BOOST_ASSERT_MSG(m_len == m_len_1 + m_len_2,
                             "Invalid XMSS WOTS parameter "
                             "\"len\" detedted.");
        }

        secure_vector<uint8_t> XMSS_WOTS_Parameters::base_w(const secure_vector<uint8_t> &msg, size_t out_size) const {
            secure_vector<uint8_t> result;
            size_t in = 0;
            size_t total = 0;
            size_t bits = 0;

            for (size_t i = 0; i < out_size; i++) {
                if (bits == 0) {
                    total = msg[in];
                    in++;
                    bits += 8;
                }
                bits -= m_lg_w;
                result.push_back(static_cast<uint8_t>((total >> bits) & (m_w - 1)));
            }
            return result;
        }

        secure_vector<uint8_t> XMSS_WOTS_Parameters::base_w(size_t value) const {
            value <<= (8 - ((m_len_2 * m_lg_w) % 8));
            size_t len_2_bytes = static_cast<size_t>(std::ceil(static_cast<float>(m_len_2 * m_lg_w) / 8.f));
            secure_vector<uint8_t> result;
            XMSS_Tools::concat(result, value, len_2_bytes);
            return base_w(result, m_len_2);
        }

        void XMSS_WOTS_Parameters::append_checksum(secure_vector<uint8_t> &data) {
            size_t csum = 0;

            for (size_t i = 0; i < data.size(); i++) {
                csum += wots_parameter() - 1 - data[i];
            }

            secure_vector<uint8_t> csum_bytes = base_w(csum);
            std::move(csum_bytes.begin(), csum_bytes.end(), std::back_inserter(data));
        }
    }    // namespace crypto3
}    // namespace nil

#endif
