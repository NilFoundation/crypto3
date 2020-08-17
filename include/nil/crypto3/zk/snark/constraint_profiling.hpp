//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CONSTRAINT_PROFILING_HPP_
#define CONSTRAINT_PROFILING_HPP_

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                extern size_t constraint_profiling_indent;

                struct constraint_profiling_entry {
                    size_t indent;
                    std::string annotation;
                    size_t count;
                };

                extern std::vector<constraint_profiling_entry> constraint_profiling_table;

#define PROFILE_CONSTRAINTS(pb, annotation)                                                                 \
    for (size_t _num_constraints_before = pb.num_constraints(), _iter = (++constraint_profiling_indent, 0), \
                _cp_pos = constraint_profiling_table.size();                                                \
         _iter == 0; constraint_profiling_table.insert(                                                     \
                         constraint_profiling_table.begin() + _cp_pos,                                      \
                         constraint_profiling_entry {--constraint_profiling_indent, annotation,             \
                                                     pb.num_constraints() - _num_constraints_before}),      \
                _iter = 1)

                size_t constraint_profiling_indent = 0;
                std::vector<constraint_profiling_entry> constraint_profiling_table;

                size_t PRINT_CONSTRAINT_PROFILING() {
                    size_t accounted = 0;
                    algebra::print_indent();
                    printf("Constraint profiling:\n");
                    for (constraint_profiling_entry &ent : constraint_profiling_table) {
                        if (ent.indent == 0) {
                            accounted += ent.count;
                        }

                        algebra::print_indent();
                        for (size_t i = 0; i < ent.indent; ++i) {
                            printf("  ");
                        }
                        printf("* Number of constraints in [%s]: %zu\n", ent.annotation.c_str(), ent.count);
                    }

                    constraint_profiling_table.clear();
                    constraint_profiling_indent = 0;

                    return accounted;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CONSTRAINT_PROFILING_HPP_
