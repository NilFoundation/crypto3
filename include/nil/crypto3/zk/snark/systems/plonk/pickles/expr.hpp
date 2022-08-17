#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_EXPR_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_EXPR_HPP

#include <nil/crypto3/zk/snark/systems/plonk/pickles/permutation.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>

#include <cassert>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template <typename FieldType>
                FieldType::value_type unnormalized_lagrange_basis(math::basic_radix2_domain<typename FieldType::value_type>& domain, int i, 
                                                                    typename FieldType::value_type& pt){
                    typename FieldType::value_type omega_i = i < 0 ? domain.omega.pow(-i).inversed();

                    return domain.compute_vanishing_polynomial(pt) / (pt - omega_i);
                }

                struct LookupPattern {
                    enum lookup_pattern_type{
                        ChaCha,
                        ChaChaFinal,
                        LookupGate,
                        RangeCheckGate,
                    };
                };

                struct Column{
                    enum column_type {
                        Witness,
                        Z,
                        LookupSorted,
                        LookupAggreg,
                        LookupTable,
                        LookupKindIndex,
                        LookupRuntimeSelector,
                        LookupRuntimeTable,
                        Index,
                        Coefficient
                    };

                    column_type column;
                    std::size_t witness_value;
                    std::size_t lookup_sorted_value;
                    LookupPattern::lookup_pattern_type lookup_kind_index_value;
                    GateType index_value;
                    std::size_t coefficient_value;
                };

                enum struct CurrOrNext{
                    Curr = 0,
                    Next = 1,
                };

                struct Variable{
                    Column col;
                    CurrOrNext row;

                    template<typename FieldType>
                    typename FieldType::value_type evaluate(std::vector<proof_evaluation_type<typename FieldType>> &evals){
                        proof_evaluation_type<typename FieldType> temp_eval = evals[row];

                        if(col == Column::Witness){
                            return evals.w[i];
                        }
                        else if(col == Column::Z){
                            return evals.z;
                        }
                        else if(col == Column::LookupSorted){
                            return evals.lookup.sorted[i];
                        }
                        else if(col == Column::LookupAggreg){
                            return evals.lookup.aggreg;
                        }
                        else if(col == Column::LookupTable){
                            return evals.lookup.table;
                        }
                        else if(col == Column::LookupRuntimeTable){
                            return evals.lookup.runtime;
                        }
                        else if(col == Column::Index && index_value == GateType::Poseidon){
                            return evals.poseidon_selector;
                        }
                        else if(col == Column::Index && index_value == GateType::Generic){
                            return evals.generic_selector;
                        }

                        return FieldType::value_type();
                    }
                }

                template <typename FieldType>
                struct PolishToken {
                    // typedef typename CurveType::scalar_field_type scalar_field_type;
                    // typedef proof_evaluation_type<FieldType> 
                    enum token_type{
                        Alpha,
                        Beta,
                        Gamma,
                        JointCombiner,
                        EndoCoefficient,
                        Mds,
                        Literal,
                        Cell,
                        Dup,
                        Pow,
                        Add,
                        Mul,
                        Sub,
                        VanishesOnLast4Rows,
                        UnnormalizedLagrangeBasis,
                        Store,
                        Load
                    };

                    token_type token;
                    std::pair<std::size_t, std::size_t> mds_value;
                    typename FieldType::value_type literal_value;
                    Variable cell_value;
                    std::size_t pow_value;
                    int unnormalized_lagrange_basis_value;
                    std::size_t load_value;
                    
                    static FieldType::value_type evaluate(std::vector<PolishToken<FieldType>>& toks,
                                                            math::basic_radix2_domain<typename FieldType>& domain,
                                                            FieldType::value_type pt, std::vector<proof_evaluation_type<typename FieldType>>& evals,
                                                            Constants<typename FieldType>& c){
                        std::vector<typename FieldType::value_type> stack, cache;

                        for(auto &t : toks){
                            if(t.token == token_type::Alpha){
                                stack.push_back(c.alpha);
                            }
                            else if(t.token == token_type::Beta){
                                stack.push_back(c.beta);
                            }
                            else if(t.token == token_type::Gamma){
                                stack.push_back(c.gamma);
                            }
                            else if(t.token == token_type::EndoCoefficient){
                                stack.push_back(c.endo_coefficient);
                            }
                            else if(t.token == token_type::Mds){
                                stack.push_back(c.mds[mds_value.first][mds_value.second]);
                            }
                            else if(t.token == token_type::VanishesOnLast4Rows){
                                stack.push_back(eval_vanishes_on_last_4_rows(domain, pt));
                            }   
                            else if(t.token == token_type::UnnormalizedLagrangeBasis){
                                stack.push_back(unnormalized_lagrange_basis(domain, unnormalized_lagrange_basis_value, pt));
                            }   
                            else if(t.token == token_type::Literal){
                                stack.push_back(t.literal_value);
                            }   
                            else if(t.token == token_type::Dup){
                                stack.push_back(stack.back());
                            }   
                            else if(t.token == token_type::Cell){
                                stack.push_back(cell_value.evaluate(evals));
                            }   
                            else if(t.token == token_type::Pow){
                                stack.back().pow(pow_value)
                            }   
                            else if(t.token == token_type::Add){
                                typename FieldType::value_type y = stack.back();
                                stack.pop_back();
                                typename FieldType::value_type x = stack.back();
                                stack.pop_back();

                                stack.push_back(x + y);
                            }   
                            else if(t.token == token_type::Mul){
                                typename FieldType::value_type y = stack.back();
                                stack.pop_back();
                                typename FieldType::value_type x = stack.back();
                                stack.pop_back();

                                stack.push_back(x * y);
                            }   
                            else if(t.token == token_type::Sub){
                                typename FieldType::value_type y = stack.back();
                                stack.pop_back();
                                typename FieldType::value_type x = stack.back();
                                stack.pop_back();

                                stack.push_back(x - y);
                            }   
                            else if(t.token == token_type::Store){
                                cache.push_back(stack.back());
                            }   
                            else if(t.token == token_type::Load){
                                stack.push_back(cache[load_value]);
                            }   

                            assert(stack.size(), 1);
                            return stack.front();
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_EXPR_HPP
