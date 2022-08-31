#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_CONSTRAINTS_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_CONSTRAINTS_HPP

#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                struct ConstraintSystem{
                    typedef typename FieldType::value_type value_type;
                    // typedef proof_evaluation_type<value_type> proof_evaluation_type;

                    constexpr static const std::size_t CONSTRAINTS = 3;
                    constexpr static const std::size_t ZK_ROWS = 3;
                    constexpr static const std::size_t GENERIC_REGISTERS = 3;

                    static value_type perm_scalars(std::vector<proof_evaluation_type<value_type>>& e, value_type beta,
                                value_type& gamma, std::vector<value_type>& alphas, 
                                value_type& zkp_zeta){
                        value_type res = e[1].z * beta * alphas.front() * zkp_zeta;
                        for(int i = 0; i < std::min(e[0].w.size(), e[0].s.size()); ++i){
                            res *= (gamma + (beta * e[0].s[i]) + e[0].w[i]);
                        }

                        return -res;
                    }

                    static void generic_gate(std::vector<value_type>& res, const value_type& alpha_pow,
                                             const std::size_t register_offset, const value_type& generic_zeta, 
                                             const std::array<value_type, kimchi_constant::COLUMNS>& w_zeta){
                        value_type alpha_generic = alpha_pow * generic_zeta;

                        // addition
                        res.push_back(alpha_generic * w_zeta[register_offset]);
                        res.push_back(alpha_generic * w_zeta[register_offset + 1]);
                        res.push_back(alpha_generic * w_zeta[register_offset + 2]);

                        // multiplication
                        res.push_back(alpha_generic * w_zeta[register_offset] * w_zeta[register_offset + 1]);

                        // constant
                        res.push_back(alpha_generic);
                    }
                    static std::vector<value_type> gnrc_scalars(const std::vector<value_type>& alphas, 
                                                                const std::array<value_type, kimchi_constant::COLUMNS>& w_zeta,
                                                                const value_type& generic_zeta){
                        std::vector<value_type> res;

                        generic_gate(res, alphas[0], 0, generic_zeta, w_zeta);
                        generic_gate(res, alphas[1], GENERIC_REGISTERS, generic_zeta, w_zeta);

                        return res;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil


#endif