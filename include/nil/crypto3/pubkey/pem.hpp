#ifndef CRYPTO3_PEM_HPP_
#define CRYPTO3_PEM_HPP_

#include <nil/crypto3/utilities/secmem.hpp>

#include <string>

namespace nil {
    namespace crypto3 {

        class data_source;

        namespace pem_code {

/**
* Encode some binary data in PEM format
* @param data binary data to encode
* @param data_len length of binary data in bytes
* @param label PEM label put after BEGIN and END
* @param line_width after this many characters, a new line is inserted
*/


            std::string encode(const uint8_t data[], size_t data_len, const std::string &label, size_t line_width = 64);

/**
* Encode some binary data in PEM format
* @param data binary data to encode
* @param label PEM label
* @param line_width after this many characters, a new line is inserted
*/
            template<typename Alloc>
            std::string encode(const std::vector<uint8_t, Alloc> &data, const std::string &label,
                               size_t line_width = 64) {
                return encode(data.data(), data.size(), label, line_width);
            }

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/


            secure_vector<uint8_t> decode(data_source &pem, std::string &label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/


            secure_vector<uint8_t> decode(const std::string &pem, std::string &label);

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is what we expect the label to be
*/


            secure_vector<uint8_t> decode_check_label(data_source &pem, const std::string &label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is what we expect the label to be
*/


            secure_vector<uint8_t> decode_check_label(const std::string &pem, const std::string &label);

/**
* Heuristic test for PEM data.
*/


            bool matches(data_source &source, const std::string &extra = "", size_t search_range = 4096);

        }
    }
}

#endif
