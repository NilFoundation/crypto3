//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
//               2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#pragma once

#include <vector>
#include <string>

namespace nil {
    namespace blueprint {
        struct configuration {
            struct coordinates {
                std::size_t row;
                std::size_t column;

                coordinates() = default;
                coordinates(std::size_t row_, std::size_t column_) : row(row_), column(column_) {};
                coordinates(std::pair<std::size_t, std::size_t> pair) : row(pair.first), column(pair.second) {};

                bool operator==(const coordinates &other) const {
                    return row == other.row && column == other.column;
                }

                bool operator<(const coordinates &other) const {
                    return row < other.row || (row == other.row && column < other.column);
                }
            };

            // In constraints we use such notation: constr[0] - result,
            // constr[1]... - arguments for lookup, linear elements for regular constraints in correct order.
            coordinates first_coordinate;
            coordinates last_coordinate;
            std::vector<coordinates> copy_to;
            std::vector<std::vector<coordinates>> constraints;
            std::vector<std::vector<coordinates>> lookups;
            coordinates copy_from;
            std::string name;

            configuration() = default;
            configuration(
                std::pair<std::size_t, std::size_t>
                    first_coordinate_,
                std::pair<std::size_t, std::size_t>
                    last_coordinate_,
                std::vector<std::pair<std::size_t, std::size_t>>
                    copy_to_,
                std::vector<std::vector<std::pair<std::size_t, std::size_t>>>
                    constraints_,
                std::vector<std::vector<std::pair<std::size_t, std::size_t>>>
                    lookups_,
                std::pair<std::size_t, std::size_t>
                    copy_from_
            ) {
                first_coordinate = coordinates(first_coordinate_);
                last_coordinate = coordinates(last_coordinate_);
                for (std::size_t i = 0; i < copy_to_.size(); ++i) {
                    copy_to.push_back(coordinates(copy_to_[i]));
                }
                for (std::size_t i = 0; i < constraints_.size(); ++i) {
                    std::vector<coordinates> constr;
                    for (std::size_t j = 0; j < constraints_[i].size(); ++j) {
                        constr.push_back(coordinates(constraints_[i][j]));
                    }
                    constraints.push_back(constr);
                }
                for (std::size_t i = 0; i < lookups_.size(); ++i) {
                    std::vector<coordinates> lookup;
                    for (std::size_t j = 0; j < lookups_[i].size(); ++j) {
                        lookup.push_back(coordinates(lookups_[i][j]));
                    }
                    lookups.push_back(lookup);
                }
                copy_from = coordinates(copy_from_);
            };

            bool operator==(const configuration &other) const {
                return first_coordinate == other.first_coordinate && last_coordinate == other.last_coordinate &&
                        copy_to == other.copy_to && constraints == other.constraints &&
                        lookups == other.lookups && copy_from == other.copy_from;
            }

            bool operator<(const configuration &other) const {
                return first_coordinate < other.first_coordinate ||
                        (first_coordinate == other.first_coordinate && last_coordinate < other.last_coordinate);
            }
        };
    }    // namespace blueprint
}    // namespace nil
