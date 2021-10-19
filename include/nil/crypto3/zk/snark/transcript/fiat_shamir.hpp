//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
#define CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ...>
                struct fiat_shamir_heuristic_manifest {
                    enum challenges_ids{

                    }

                    typedef ... preprocessor;

                    typedef std::tuple<...> processors;

                    struct transcript_manifest {
                        using challenges_ids = typename Manifest::challenges_ids;

                        using processors = typename Manifest::processors;

                        using challenges = std::array<, std::tuple_size<processors>>;

                        using result = typename Hash::digest_type;
                    }
                }

                /*!
                 * @brief Fiat–Shamir heuristic.
                 * @tparam Hash Hash function, which serves as a non-interactive random oracle.
                 *
                 */
                template<fiat_shamir_heuristic_manifest Manifest, typename Hash>
                class fiat_shamir_heuristic : public transcript<typename Manifest::transcript_manifest>{

                    typedef transcript<typename Manifest::transcript_manifest> transcript_type;

                    template <typename Manifest::challenges_ids challenge_id>
                    bool set_challenge(std::tuple_element<challenge_id, typename Manifest::transcript_manifest::challenges> value){
                        return transcript_type::set_challenge(value);
                    }

                    preprocessor::input_type input_value 
                    preprocessor::random_value_type random_value;

                public:
                    
                    fiat_shamir_heuristic(preprocessor::input_type input_value) 
                        : transcript_type(), input_value(input_value){
                        random_value = algebra::random_element<...>();
                    }

                    template <typename Manifest::challenges_ids challenge_id>
                    std::tuple_element<challenge_id, typename Manifest::transcript_manifest::challenges> get_challenge() const{
                        transcript_type::get_challenge<challenge_id>();
                    }

                    template <typename Manifest::challenges_ids challenge_id>
                    std::tuple_element<challenge_id, typename Manifest::processors>::result_type get_challenge_result(){
                        
                        set_challenge<challenge_id>(hash<Hash>(get_challenge_result<challenge_id - 1>()));

                        transcript_type::get_challenge_result();
                    }

                    template <>
                    std::tuple_element<challenge_id, typename Manifest::processors>::result_type get_challenge_result<0>(){
                        return preprocessor(input_value, random_value);
                    }

                    typename Manifest::result export(){

                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
