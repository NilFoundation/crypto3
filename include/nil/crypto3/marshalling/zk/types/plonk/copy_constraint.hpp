#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                // *********************** Plonk copy constraint **************************** //
                template<typename TTypeBase, typename VariableType>
                    using plonk_copy_constraint = nil::marshalling::types::bundle<TTypeBase, std::tuple<
                        typename variable<TTypeBase, VariableType>::type,
                        typename variable<TTypeBase, VariableType>::type
                    >>;

                template<typename Endianness, typename VariableType>
                plonk_copy_constraint<typename nil::marshalling::field_type<Endianness>, VariableType>
                fill_plonk_copy_constraint(const std::pair<VariableType, VariableType> &copy_constraint){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_copy_constraint<TTypeBase, VariableType>;

                    return result_type(
                        std::make_tuple(
                            fill_variable<Endianness, VariableType>(std::get<0>(copy_constraint)),
                            fill_variable<Endianness, VariableType>(std::get<1>(copy_constraint))
                        )
                    );
                }

                template<typename Endianness, typename VariableType>
                std::pair<VariableType, VariableType>
                make_plonk_copy_constraint(const plonk_copy_constraint<typename nil::marshalling::field_type<Endianness>, VariableType> &filled_copy_constraint
                ){

                    return std::make_pair(
                        make_variable<Endianness, VariableType>(std::get<0>(filled_copy_constraint.value())),
                        make_variable<Endianness, VariableType>(std::get<1>(filled_copy_constraint.value()))
                    );
                }


                // *********************** Plonk copy constraints **************************** //
                template<typename TTypeBase, typename VariableType>
                using plonk_copy_constraints = nil::marshalling::types::array_list<
                    TTypeBase,
                    plonk_copy_constraint<TTypeBase, VariableType>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename VariableType>
                plonk_copy_constraints<nil::marshalling::field_type<Endianness>,  VariableType>
                fill_plonk_copy_constraints(const std::vector<std::pair<VariableType, VariableType>> &constraints) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    plonk_copy_constraints<TTypeBase, VariableType> filled_constraints;
                    for (const auto &constraint : constraints) {
                        filled_constraints.value().push_back(
                            fill_plonk_copy_constraint< Endianness, VariableType>(constraint)
                        );
                    }

                    return filled_constraints;
                }

                template<typename Endianness, typename VariableType>
                std::vector<std::pair<VariableType, VariableType> >
                make_plonk_copy_constraints(
                    const plonk_copy_constraints<nil::marshalling::field_type<Endianness>, VariableType> &filled_constraints
                ){
                    std::vector< std::pair< VariableType, VariableType > > constraints;
                    for (std::size_t i = 0; i < filled_constraints.value().size(); i++) {
                        constraints.emplace_back(make_plonk_copy_constraint<Endianness, VariableType>(filled_constraints.value()[i]));
                    }
                    return constraints;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP
