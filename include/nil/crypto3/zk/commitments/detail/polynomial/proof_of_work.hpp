//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef PROOF_OF_WORK_HPP
#define PROOF_OF_WORK_HPP

#include <boost/property_tree/ptree.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename TranscriptHashType, typename OutType = std::uint32_t, std::uint32_t MASK=0xFFFF0000>
                class proof_of_work {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using output_type = OutType;

                    constexpr static std::uint32_t mask = MASK;

                    static inline boost::property_tree::ptree get_params() {
                        boost::property_tree::ptree params;
                        params.put("mask", mask);
                        return params;
                    }

                    static inline OutType generate(transcript_type &transcript) {
                        output_type proof_of_work = std::rand();
                        output_type result;
                        std::vector<std::uint8_t> bytes(4);

                        while( true ) {
                            transcript_type tmp_transcript = transcript;
                            bytes[0] = std::uint8_t((proof_of_work&0xFF000000)>>24);
                            bytes[1] = std::uint8_t((proof_of_work&0x00FF0000)>>16);
                            bytes[2] = std::uint8_t((proof_of_work&0x0000FF00)>>8);
                            bytes[3] = std::uint8_t(proof_of_work&0x000000FF);

                            tmp_transcript(bytes);
                            result = tmp_transcript.template int_challenge<output_type>();
                            if ((result & mask) == 0)
                                break;
                            proof_of_work++;
                        }
                        transcript(bytes);
                        result = transcript.template int_challenge<output_type>();
                        return proof_of_work;
                    }

                    static inline bool verify(transcript_type &transcript, output_type proof_of_work) {
                        std::vector<std::uint8_t> bytes(4);
                        bytes[0] = std::uint8_t((proof_of_work&0xFF000000)>>24);
                        bytes[1] = std::uint8_t((proof_of_work&0x00FF0000)>>16);
                        bytes[2] = std::uint8_t((proof_of_work&0x0000FF00)>>8);
                        bytes[3] = std::uint8_t(proof_of_work&0x000000FF);
                        transcript(bytes);
                        output_type result = transcript.template int_challenge<output_type>();
                        return ((result & mask) == 0);
                    }
                };
            }
        }
    }
}

#endif
