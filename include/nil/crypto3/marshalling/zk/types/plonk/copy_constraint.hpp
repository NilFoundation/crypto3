#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>

#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                /*********************** Plonk copy constraint ****************************/
                template<typename TTypeBase, typename FieldType> 
                    using plonk_copy_constraint = nil::marshalling::types::bundle<TTypeBase, std::tuple<
                        typename variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>>::type, 
                        typename variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>>::type
                    >>;

                template<typename FieldType, typename Endianness> 
                nil::crypto3::marshalling::types::plonk_copy_constraint<typename nil::marshalling::field_type<Endianness>, FieldType>
                fill_plonk_copy_constraint(const nil::crypto3::zk::snark::plonk_copy_constraint<FieldType> &copy_constraint){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using VariableType = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;
                    using result_type = nil::crypto3::marshalling::types::plonk_copy_constraint<TTypeBase, FieldType>;

                    return result_type(
                        std::make_tuple(
                            fill_variable<VariableType, Endianness>(std::get<0>(copy_constraint)),
                            fill_variable<VariableType, Endianness>(std::get<1>(copy_constraint))
                        )
                    );
                }

                template<typename FieldType, typename Endianness>
                nil::crypto3::zk::snark::plonk_copy_constraint<FieldType>
                make_plonk_copy_constraint(const nil::crypto3::marshalling::types::plonk_copy_constraint<
                    typename nil::marshalling::field_type<Endianness>, 
                    FieldType> &filled_copy_constraint){

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using VariableType = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;
                    using result_type = nil::crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                    return std::make_pair(
                        make_variable<VariableType, Endianness>(std::get<0>(filled_copy_constraint.value())),
                        make_variable<VariableType, Endianness>(std::get<1>(filled_copy_constraint.value()))
                    );      
                }


                /*********************** Plonk copy constraints ****************************/
                template<typename TTypeBase, typename FieldType>
                using plonk_copy_constraints = nil::marshalling::types::array_list<
                    TTypeBase, 
                    plonk_copy_constraint<TTypeBase, FieldType>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename FieldType, typename Endianness>
                plonk_copy_constraints<nil::marshalling::field_type<Endianness>,  FieldType>
                fill_plonk_copy_constraints(const std::vector< nil::crypto3::zk::snark::plonk_copy_constraint<FieldType>> &constraints) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    plonk_copy_constraints<TTypeBase, FieldType> filled_constraints;
                    for (const auto &constraint : constraints) {
                        filled_constraints.value().push_back(
                            fill_plonk_copy_constraint< FieldType, Endianness>(constraint)
                        );
                    }

                    return filled_constraints;
                }

                template<typename FieldType, typename Endianness>
                std::vector< nil::crypto3::zk::snark::plonk_copy_constraint<FieldType> >
                make_plonk_copy_constraints(
                    const plonk_copy_constraints<nil::marshalling::field_type<Endianness>, FieldType> &filled_constraints
                ){
                    std::vector< nil::crypto3::zk::snark::plonk_copy_constraint<FieldType> > constraints;
                    for (auto i = 0; i < filled_constraints.value().size(); i++) {
                        constraints.emplace_back(make_plonk_copy_constraint<FieldType, Endianness>(filled_constraints.value()[i]));
                    }
                    return constraints;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_COPY_CONSTRAINT_HPP
