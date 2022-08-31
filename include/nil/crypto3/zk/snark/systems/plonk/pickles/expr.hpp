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
                typename FieldType::value_type unnormalized_lagrange_basis(math::basic_radix2_domain<FieldType> domain, int i, 
                                                                    typename FieldType::value_type pt){
                    typename FieldType::value_type omega_i = i < 0 ? domain.omega.pow(-i).inversed() : domain.omega.pow(i);

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

                struct Column{

                    Column(gate_type gate) : column(column_type::Index), index_value(gate) {}

                    Column(column_type column, std::size_t value) : column(column), witness_value(value),
                            lookup_sorted_value(value), coefficient_value(value) {}

                    Column() = default;

                    column_type column;
                    std::size_t witness_value;
                    std::size_t lookup_sorted_value;
                    LookupPattern::lookup_pattern_type lookup_kind_index_value;
                    gate_type index_value;
                    std::size_t coefficient_value;
                };

                enum CurrOrNext{
                    Curr = 0,
                    Next = 1,
                };

                struct Variable{
                    Column col;
                    CurrOrNext row;

                    Variable(Column col, CurrOrNext row = CurrOrNext::Curr) : col(col), row(row) {}

                    Variable() = default;
                };

                template<typename FieldType>
                typename FieldType::value_type variable_evaluate(Variable& var, std::vector<proof_evaluation_type<typename FieldType::value_type>> &evals){
                    proof_evaluation_type<typename FieldType::value_type> temp_eval = evals[var.row];

                    if(var.col.column == column_type::Witness){
                        return temp_eval.w[var.col.witness_value];
                    }
                    else if(var.col.column == column_type::Z){
                        return temp_eval.z;
                    }
                    else if(var.col.column == column_type::LookupSorted){
                        return temp_eval.lookup.sorted[var.col.lookup_sorted_value];
                    }
                    else if(var.col.column == column_type::LookupAggreg){
                        return temp_eval.lookup.aggreg;
                    }
                    else if(var.col.column == column_type::LookupTable){
                        return temp_eval.lookup.table;
                    }
                    else if(var.col.column == column_type::LookupRuntimeTable){
                        return temp_eval.lookup.runtime;
                    }
                    else if(var.col.column == column_type::Index && var.col.index_value == gate_type::Poseidon){
                        return temp_eval.poseidon_selector;
                    }
                    else if(var.col.column == column_type::Index && var.col.index_value == gate_type::Generic){
                        return temp_eval.generic_selector;
                    }

                    return typename FieldType::value_type();
                }

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

                template <typename FieldType>
                struct PolishToken {
                    // typedef typename CurveType::scalar_field_type scalar_field_type;
                    // typedef proof_evaluation_type<FieldType> 

                    token_type token;
                    std::pair<std::size_t, std::size_t> mds_value;
                    typename FieldType::value_type literal_value;
                    Variable cell_value;
                    std::size_t pow_value;
                    int unnormalized_lagrange_basis_value;
                    std::size_t load_value;

                    PolishToken(token_type token) : token(token) {}

                    PolishToken(std::pair<std::size_t, std::size_t> mds_value) : token(token_type::Mds), mds_value(mds_value) {}

                    PolishToken(typename FieldType::value_type literal_value) : token(token_type::Literal), literal_value(literal_value) {}

                    PolishToken(Variable cell_value) : token(token_type::Cell), cell_value(cell_value) {}

                    PolishToken(token_type token, std::size_t value) : token(token), pow_value(value), load_value(value) {}

                    PolishToken(int unnormalized_lagrange_basis_value) : token(token), 
                            unnormalized_lagrange_basis_value(unnormalized_lagrange_basis_value) {} 
                    
                    static typename FieldType::value_type evaluate(std::vector<PolishToken<FieldType>>& toks,
                                                            math::basic_radix2_domain<FieldType>& domain,
                                                            typename FieldType::value_type pt, 
                                                            std::vector<proof_evaluation_type<typename FieldType::value_type>>& evals,
                                                            Constants<FieldType>& c){
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
                            else if(t.token == token_type::JointCombiner){
                                stack.push_back(c.joint_combiner);
                            }
                            else if(t.token == token_type::EndoCoefficient){
                                stack.push_back(c.endo_coefficient);
                            }
                            else if(t.token == token_type::Mds){
                                stack.push_back(c.mds[t.mds_value.first][t.mds_value.second]);
                            }
                            else if(t.token == token_type::VanishesOnLast4Rows){
                                stack.push_back(eval_vanishes_on_last_4_rows(domain, pt));
                            }   
                            else if(t.token == token_type::UnnormalizedLagrangeBasis){
                                stack.push_back(unnormalized_lagrange_basis<FieldType>(domain, t.unnormalized_lagrange_basis_value, pt));
                            }   
                            else if(t.token == token_type::Literal){
                                stack.push_back(t.literal_value);
                            }
                            else if(t.token == token_type::Dup){
                                stack.push_back(stack.back());
                            }   
                            else if(t.token == token_type::Cell){
                                stack.push_back(variable_evaluate<FieldType>(t.cell_value, evals));
                            }   
                            else if(t.token == token_type::Pow){
                                stack.back() = stack.back().pow(t.pow_value);
                            }   
                            else if(t.token == token_type::Add){
                                assert(stack.size() > 1);
                                typename FieldType::value_type y = stack.back();
                                stack.pop_back();
                                typename FieldType::value_type x = stack.back();
                                stack.pop_back();

                                stack.push_back(x + y);
                            }   
                            else if(t.token == token_type::Mul){
                                assert(stack.size() > 1);
                                typename FieldType::value_type y = stack.back();
                                stack.pop_back();
                                typename FieldType::value_type x = stack.back();
                                stack.pop_back();

                                stack.push_back(x * y);
                            }   
                            else if(t.token == token_type::Sub){
                                assert(stack.size() > 1);
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
                                stack.push_back(cache[t.load_value]);
                            }   
                        }

                        assert(stack.size() == 1);
                        return stack.front();
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_EXPR_HPP
