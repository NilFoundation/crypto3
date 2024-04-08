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
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                // *********************** Plonk copy constraint **************************** //
                template<typename TTypeBase, typename FieldType>
                    using plonk_copy_constraint = nil::marshalling::types::bundle<TTypeBase, std::tuple<
                        typename variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>>::type,
                        typename variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>>::type
                    >>;

                template<typename Endianness, typename FieldType>
                plonk_copy_constraint<typename nil::marshalling::field_type<Endianness>, FieldType>
                fill_plonk_copy_constraint(const nil::crypto3::zk::snark::plonk_copy_constraint<FieldType> &copy_constraint){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_copy_constraint<TTypeBase, FieldType>;
                    using VariableType = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

                    return result_type(
                        std::make_tuple(
                            fill_variable<Endianness, VariableType>(copy_constraint.first),
                            fill_variable<Endianness, VariableType>(copy_constraint.second)
                        )
                    );
                }

                template<typename Endianness, typename FieldType>
                nil::crypto3::zk::snark::plonk_copy_constraint<FieldType>
                make_plonk_copy_constraint(const plonk_copy_constraint<typename nil::marshalling::field_type<Endianness>, FieldType> &filled_copy_constraint
                ){
                    using VariableType = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;
                    return nil::crypto3::zk::snark::plonk_copy_constraint<FieldType>(
                        make_variable<Endianness, VariableType>(std::get<0>(filled_copy_constraint.value())),
                        make_variable<Endianness, VariableType>(std::get<1>(filled_copy_constraint.value()))
                    );
                }


                // *********************** Plonk copy constraints **************************** //
                template<typename TTypeBase, typename FieldType>
                using plonk_copy_constraints = nil::marshalling::types::array_list<
                    TTypeBase,
                    plonk_copy_constraint<TTypeBase, FieldType>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename FieldType>
                plonk_copy_constraints<nil::marshalling::field_type<Endianness>,  FieldType>
                fill_plonk_copy_constraints(const std::vector<nil::crypto3::zk::snark::plonk_copy_constraint<FieldType>> &constraints) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    plonk_copy_constraints<TTypeBase, FieldType> filled_constraints;
                    for (const auto &constraint : constraints) {
                        filled_constraints.value().push_back(
                            fill_plonk_copy_constraint< Endianness, FieldType >(constraint)
                        );
                    }

                    return filled_constraints;
                }

                template<typename Endianness, typename FieldType>
                std::vector<nil::crypto3::zk::snark::plonk_copy_constraint<FieldType> >
                make_plonk_copy_constraints(
                    const plonk_copy_constraints<nil::marshalling::field_type<Endianness>, FieldType> &filled_constraints
                ){
                    std::vector< nil::crypto3::zk::snark::plonk_copy_constraint<FieldType> > constraints;
                    for (std::size_t i = 0; i < filled_constraints.value().size(); i++) {
                        constraints.emplace_back(make_plonk_copy_constraint<Endianness, FieldType>(filled_constraints.value()[i]));
                    }
                    return constraints;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP
