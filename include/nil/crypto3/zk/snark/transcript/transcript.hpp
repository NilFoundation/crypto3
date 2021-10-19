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

#ifndef CRYPTO3_ZK_TRANSCRIPT_HPP
#define CRYPTO3_ZK_TRANSCRIPT_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                struct transcript_manifest {
                    enum challenges_ids{

                    }

                    typedef std::tuple<...> challenges;

                    typedef std::tuple<...> processors;

                    typedef ... result;
                }

                /*!
                 * @brief Transcript policy. Assumed to be inherited by particular algorithms.
                 * @tparam TChallenges Enum of challenge IDs.
                 *
                 */
                template<transcript_manifest Manifest>
                class transcript {

                    typename Manifest::challenges challenges;

                    std::size_t next_challenge_id = 0;
                public:
                    
                    transcript (){}

                    transcript (std::tuple<> in_challenges): challenges(in_challenges){

                    }

                    template <typename Manifest::challenges_ids challenge_id>
                    bool set_challenge(std::tuple_element<challenge_id, typename Manifest::challenges> value){
                        std::get<challenge_id>(challenges) = value;

                        return (challenge_id == next_challenge_id++);
                    }                    

                    template <typename Manifest::challenges_ids challenge_id>
                    std::tuple_element<challenge_id, typename Manifest::challenges> get_challenge() const{
                        return std::get<challenge_id>(challenges);
                    }

                    template <typename Manifest::challenges_ids challenge_id>
                    std::tuple_element<challenge_id, typename Manifest::processors>::result_type get_challenge_result(){
                        return std::tuple_element<challenge_id, typename Manifest::processors>(
                            std::get<challenge_id>(challenges));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TRANSCRIPT_HPP
