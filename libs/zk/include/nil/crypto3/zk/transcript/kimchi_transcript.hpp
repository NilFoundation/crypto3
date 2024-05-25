#ifndef CRYPTO3_ZK_SPONGE_HPP
#define CRYPTO3_ZK_SPONGE_HPP

#include <vector>
#include <array>
#include <iostream>
#include <cstdint>
#include <algorithm>

#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/mapping.hpp>
// #include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark{
                template<typename value_type>
                struct proof_evaluation_type;
            }
            namespace transcript {
                constexpr static const int CHALLENGE_LENGTH_IN_LIMBS = 2;
                constexpr static const int HIGH_ENTROPY_LIMBS = 2;

                template <typename integral_type>
                integral_type pack(std::vector<uint64_t> limbs_lsb){
                    nil::marshalling::status_type status;
                    std::size_t byte_size = nil::crypto3::multiprecision::backends::max_precision<typename integral_type::backend_type>::value / CHAR_BIT;
                    std::size_t size = byte_size / sizeof(uint64_t) + (byte_size % sizeof(uint64_t) ? 1 : 0);
                    limbs_lsb.resize(size);
                    std::reverse(limbs_lsb.begin(), limbs_lsb.end());

                    integral_type res = nil::marshalling::pack<nil::marshalling::option::big_endian>(limbs_lsb, status);

                    return res;
                }

                template <typename value_type, typename integral_type>
                std::vector<std::uint64_t> unpack(value_type& value){
                    nil::marshalling::status_type status;
                    integral_type scalar_value = integral_type(value.data);
                    std::vector<std::uint64_t> limbs_lsb = nil::marshalling::pack<nil::marshalling::option::big_endian>(scalar_value, status);

                    std::reverse(limbs_lsb.begin(), limbs_lsb.end());
                    limbs_lsb.resize(CHALLENGE_LENGTH_IN_LIMBS);

                    return limbs_lsb;
                }

                template <typename CurveType>
                struct BaseSponge{
                    typedef typename CurveType::template g1_type<algebra::curves::coordinates::affine> group_type;
                    typedef typename CurveType::base_field_type base_field_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef nil::crypto3::hashes::detail::mina_poseidon_policy<base_field_type> policy_type;
                    
                    constexpr static const int CHALLENGE_LENGTH_IN_LIMBS = 2;
                    constexpr static const int HIGH_ENTROPY_LIMBS = 2;
                    
                    typedef snark::ScalarChallenge<scalar_field_type> scalar_challenge_type;

                    typedef std::uint64_t limb_type;

                    typename nil::crypto3::hashes::detail::poseidon_sponge_construction<policy_type> sponge;
                    std::vector<limb_type> last_squeezed;

                };

                template <typename CurveType>
                struct DefaultFrSponge : public BaseSponge<CurveType> {
                    typedef typename BaseSponge<CurveType>::group_type group_type;
                    typedef typename BaseSponge<CurveType>::scalar_field_type scalar_field_type;
                    // typedef typename BaseSponge<CurveType>::scalar_field_type scalar_field_type;
                    typedef typename BaseSponge<CurveType>::limb_type limb_type;
                    // typedef typename BaseSponge<CurveType>::scalar_challenge_type scalar_challenge_type;
                    
                    typedef nil::crypto3::hashes::detail::mina_poseidon_policy<scalar_field_type> policy_type;
                    typename nil::crypto3::hashes::detail::poseidon_sponge_construction<policy_type> sponge;
                    typedef snark::ScalarChallenge<scalar_field_type> scalar_challenge_type;

                    constexpr static const int CHALLENGE_LENGTH_IN_LIMBS = BaseSponge<CurveType>::CHALLENGE_LENGTH_IN_LIMBS;
                    constexpr static const int HIGH_ENTROPY_LIMBS = BaseSponge<CurveType>::HIGH_ENTROPY_LIMBS;

                    typename scalar_field_type::value_type squeeze(std::size_t num_limbs){
                        if(this->last_squeezed.size() >= num_limbs){
                            std::vector<limb_type> limbs(this->last_squeezed.begin(), this->last_squeezed.begin() + num_limbs);
                            std::vector<limb_type> remaining(this->last_squeezed.begin() + num_limbs, this->last_squeezed.end());
                            this->last_squeezed = remaining;
                            
                            return typename scalar_field_type::value_type(pack<typename scalar_field_type::integral_type>(limbs));
                        }
                        else{
                            auto sq = this->sponge.squeeze();
                            nil::marshalling::status_type status;
                            std::vector<limb_type> x = unpack<typename scalar_field_type::value_type, typename scalar_field_type::integral_type>(sq);

                            for(int i = 0; i < HIGH_ENTROPY_LIMBS; ++i){
                                this->last_squeezed.push_back(x[i]);
                            }

                            return squeeze(num_limbs);
                        }
                    }

                    void absorb(typename scalar_field_type::value_type x){
                        this->last_squeezed.clear();
                        this->sponge.absorb(x);
                    }

                    scalar_challenge_type challenge(){
                        return scalar_challenge_type(squeeze(CHALLENGE_LENGTH_IN_LIMBS));
                    }

                    void absorb_evaluations(std::vector<typename scalar_field_type::value_type>& p,
                                            snark::proof_evaluation_type<std::vector<typename scalar_field_type::value_type>>& e){
                        this->last_squeezed.clear();
                        this->sponge.absorb(p);

                        std::vector<std::vector<typename scalar_field_type::value_type>> points = {
                                                                                                    e.z,
                                                                                                    e.generic_selector,
                                                                                                    e.poseidon_selector
                                                                                                 };
                        this->sponge.absorb(e.z);
                        this->sponge.absorb(e.generic_selector);
                        this->sponge.absorb(e.poseidon_selector);
                        
                        for(auto &w_iter : e.w){
                            this->sponge.absorb(w_iter);
                        }

                        for(auto &s_iter : e.s){
                            this->sponge.absorb(s_iter);
                        }

                        if(e.lookup_is_used){
                            for(auto &s : e.lookup.sorted){
                                this->sponge.absorb(s);
                            }

                            this->sponge.absorb(e.lookup.aggreg);
                            this->sponge.absorb(e.lookup.table);

                            if(e.lookup.runtime_is_used){
                                this->sponge.absorb(e.lookup.runtime);
                            }
                        }
                    }

                };

                template <typename CurveType>
                struct DefaultFqSponge : public BaseSponge<CurveType> {
                    typedef typename BaseSponge<CurveType>::group_type group_type;
                    typedef typename BaseSponge<CurveType>::base_field_type base_field_type;
                    typedef typename BaseSponge<CurveType>::scalar_field_type scalar_field_type;
                    typedef typename BaseSponge<CurveType>::limb_type limb_type;
                    typedef typename BaseSponge<CurveType>::scalar_challenge_type scalar_challenge_type;

                    constexpr static const int CHALLENGE_LENGTH_IN_LIMBS = BaseSponge<CurveType>::CHALLENGE_LENGTH_IN_LIMBS;
                    constexpr static const int HIGH_ENTROPY_LIMBS = BaseSponge<CurveType>::HIGH_ENTROPY_LIMBS;

                    std::vector<limb_type> squeeze_limbs(std::size_t num_limbs){
                        if(this->last_squeezed.size() >= num_limbs){
                            std::vector<limb_type> limbs(this->last_squeezed.begin(), this->last_squeezed.begin() + num_limbs);
                            std::vector<limb_type> remaining(this->last_squeezed.begin() + num_limbs, this->last_squeezed.end());
                            this->last_squeezed = remaining;
                            return limbs;
                        }
                        else{
                            auto sq = this->sponge.squeeze();
                            nil::marshalling::status_type status;

                            std::vector<limb_type> x = unpack<typename base_field_type::value_type, typename base_field_type::integral_type>(sq);

                            for(int i = 0; i < HIGH_ENTROPY_LIMBS; ++i){
                                this->last_squeezed.push_back(x[i]);
                            }

                            return squeeze_limbs(num_limbs);
                        }
                    }

                    typename base_field_type::value_type squeeze_field(){
                        this->last_squeezed.clear();
                        return this->sponge.squeeze();
                    }

                    typename scalar_field_type::value_type squeeze(std::size_t num_limbs){
                        auto limbs = this->squeeze_limbs(num_limbs);
                        nil::marshalling::status_type status;
                        auto first_value = pack<typename scalar_field_type::integral_type>(limbs);
                        typename scalar_field_type::value_type res = typename scalar_field_type::value_type(pack<typename scalar_field_type::integral_type>(limbs));
                        return res;
                    }

                    void absorb_g(std::vector<typename group_type::value_type>& gs){
                        this->last_squeezed.clear();
                        for(auto &g : gs){
                            absorb_g(g);
                        }
                    }

                    void absorb_g(typename group_type::value_type g){
                        if(!this->last_squeezed.empty())
                            this->last_squeezed.clear();

                        this->sponge.absorb(g.X);
                        this->sponge.absorb(g.Y);
                    }

                    void absorb_fr(typename scalar_field_type::value_type f){
                        if(this->last_squeezed.empty())
                            this->last_squeezed.clear();

                        if(scalar_field_type::modulus < base_field_type::modulus){
                            typename base_field_type::value_type casted_to_base_value = typename base_field_type::value_type(typename base_field_type::integral_type(f.data));
                            this->sponge.absorb(casted_to_base_value);
                        } else{
                            nil::marshalling::status_type status;
                            typename scalar_field_type::integral_type scalar_f(f.data);
                            std::vector<bool> bits = nil::marshalling::pack<nil::marshalling::option::big_endian>(scalar_f, status);

                            std::vector<bool> shifted_bits(bits.size(), false);
                            std::copy(bits.begin(), bits.end() - 1, shifted_bits.begin() + 1);

                            typename base_field_type::integral_type low_bit = bits.back() ? 
                                    typename base_field_type::integral_type(1) : typename base_field_type::integral_type(0);
                            typename base_field_type::integral_type high_bits = nil::marshalling::pack<nil::marshalling::option::big_endian>(shifted_bits, status);

                            typename base_field_type::value_type high_bits_field = typename base_field_type::value_type(high_bits);
                            typename base_field_type::value_type low_bit_field = typename base_field_type::value_type(low_bit);

                            this->sponge.absorb(high_bits_field);
                            this->sponge.absorb(low_bit_field);
                        }
                    }
                    void absorb_fr(const std::vector<typename scalar_field_type::value_type>& fs){
                        this->last_squeezed.clear();

                        for(auto f : fs){
                            absorb_fr(f);
                        }
                    }

                    typename scalar_field_type::value_type challenge() {
                        return this->squeeze(CHALLENGE_LENGTH_IN_LIMBS);
                    }

                    typename base_field_type::value_type challenge_fq() {
                        return this->squeeze_field();
                    }

                    scalar_challenge_type squeeze_prechallenge() {
                        return scalar_challenge_type(challenge());
                    }

                    typename scalar_field_type::value_type squeeze_challenge(typename scalar_field_type::value_type endo_r) {
                        return squeeze_prechallenge().to_field(endo_r);
                    }

                    typename scalar_field_type::value_type digest(){
                        return typename scalar_field_type::value_type(typename scalar_field_type::integral_type(this->squeeze_field().data));
                    }
                };
            }
        }
    }
}

#endif
