#ifndef CRYPTO3_PUBKEY_PEM_HPP
#define CRYPTO3_PUBKEY_PEM_HPP

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>
#include <nil/crypto3/codec/base.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

#include <string>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace pem_code {
                namespace detail {
                    std::string linewrap(size_t width, const std::string &in) {
                        std::string out;
                        for (size_t i = 0; i != in.size(); ++i) {
                            if (i > 0 && i % width == 0) {
                                out.push_back('\n');
                            }
                            out.push_back(in[i]);
                        }
                        if (out.size() > 0 && out[out.size() - 1] != '\n') {
                            out.push_back('\n');
                        }

                        return out;
                    }
                }    // namespace detail

                /**
                 * Encode some binary data in PEM format
                 * @param data binary data to encode
                 * @param data_len length of binary data in bytes
                 * @param label PEM label put after BEGIN and END
                 * @param line_width after this many characters, a new line is inserted
                 */

                std::string encode(const uint8_t data[], size_t data_len, const std::string &label,
                                   size_t line_width = 64) {
                    const std::string PEM_HEADER = "-----BEGIN " + label + "-----\n";
                    const std::string PEM_TRAILER = "-----END " + label + "-----\n";

                    return (PEM_HEADER + detail::linewrap(line_width, crypto3::encode<codec::base64>(data))
                            + PEM_TRAILER);
                }

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

                secure_vector<uint8_t> decode(data_source &pem, std::string &label) {
                    const size_t RANDOM_CHAR_LIMIT = 8;

                    label.clear();

                    const std::string PEM_HEADER1 = "-----BEGIN ";
                    const std::string PEM_HEADER2 = "-----";
                    size_t position = 0;

                    while (position != PEM_HEADER1.length()) {
                        uint8_t b;
                        if (!source.read_byte(b)) {
                            throw decoding_error("PEM: No PEM header found");
                        }
                        if (b == PEM_HEADER1[position]) {
                            ++position;
                        } else if (position >= RANDOM_CHAR_LIMIT) {
                            throw decoding_error("PEM: Malformed PEM header");
                        } else {
                            position = 0;
                        }
                    }
                    position = 0;
                    while (position != PEM_HEADER2.length()) {
                        uint8_t b;
                        if (!source.read_byte(b)) {
                            throw decoding_error("PEM: No PEM header found");
                        }
                        if (b == PEM_HEADER2[position]) {
                            ++position;
                        } else if (position) {
                            throw decoding_error("PEM: Malformed PEM header");
                        }

                        if (position == 0) {
                            label += static_cast<char>(b);
                        }
                    }

                    std::vector<char> b64;

                    const std::string PEM_TRAILER = "-----END " + label + "-----";
                    position = 0;
                    while (position != PEM_TRAILER.length()) {
                        uint8_t b;
                        if (!source.read_byte(b)) {
                            throw decoding_error("PEM: No PEM trailer found");
                        }
                        if (b == PEM_TRAILER[position]) {
                            ++position;
                        } else if (position) {
                            throw decoding_error("PEM: Malformed PEM trailer");
                        }

                        if (position == 0) {
                            b64.push_back(b);
                        }
                    }

                    return crypto3::decode<codec::base64>(b64);
                }

                /**
                 * Decode PEM data
                 * @param pem a string containing PEM encoded data
                 * @param label is set to the PEM label found for later inspection
                 */

                secure_vector<uint8_t> decode(const std::string &pem, std::string &label) {
                    data_source_memory src(pem);
                    return decode(src, label);
                }

                /**
                 * Decode PEM data
                 * @param pem a datasource containing PEM encoded data
                 * @param label is what we expect the label to be
                 */

                secure_vector<uint8_t> decode_check_label(data_source &pem, const std::string &label) {
                    std::string label_got;
                    secure_vector<uint8_t> ber = decode(source, label_got);
                    if (label_got != label_want) {
                        throw decoding_error("PEM: Label mismatch, wanted " + label_want + ", got " + label_got);
                    }
                    return ber;
                }

                /**
                 * Decode PEM data
                 * @param pem a string containing PEM encoded data
                 * @param label is what we expect the label to be
                 */

                secure_vector<uint8_t> decode_check_label(const std::string &pem, const std::string &label) {
                    data_source_memory src(pem);
                    return decode_check_label(src, label_want);
                }

                /**
                 * Heuristic test for PEM data.
                 */

                bool matches(data_source &source, const std::string &extra = "", size_t search_range = 4096) {
                    const std::string PEM_HEADER = "-----BEGIN " + extra;

                    secure_vector<uint8_t> search_buf(search_range);
                    size_t got = source.peek(search_buf.data(), search_buf.size(), 0);

                    if (got < PEM_HEADER.length()) {
                        return false;
                    }

                    size_t index = 0;

                    for (size_t j = 0; j != got; ++j) {
                        if (search_buf[j] == PEM_HEADER[index]) {
                            ++index;
                        } else {
                            index = 0;
                        }
                        if (index == PEM_HEADER.size()) {
                            return true;
                        }
                    }
                    return false;
                }

            }    // namespace pem_code
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
