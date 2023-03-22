template<typename FieldType, typename NonNativeFieldType>
std::array<typename FieldType::value_type, 4> chop_non_native(typename NonNativeFieldType::value_type input) {
    typename NonNativeFieldType::integral_type input_integral = typename NonNativeFieldType::integral_type(input.data);

    std::array<typename FieldType::value_type, 4> output;

    typename NonNativeFieldType::integral_type base = 1;
    typename NonNativeFieldType::integral_type mask = (base << 66) - 1;

    output[0] = input_integral & mask;
    output[1] = (input_integral >> 66) & mask;
    output[2] = (input_integral >> 132) & mask;
    output[3] = (input_integral >> 198) & mask;

    return output;
}

template<typename FieldType, typename NonNativeFieldType>
typename NonNativeFieldType::value_type glue_non_native(std::array<typename FieldType::value_type, 4> input) {
    typename NonNativeFieldType::integral_type base = 1;
    typename NonNativeFieldType::integral_type chunk_size = (base << 66);

    std::array<typename FieldType::integral_type, 4> input_integral;

    for (std::size_t i = 0; i < input.size(); i++) {
        assert(input[i] < chunk_size);
        input_integral[i] = typename FieldType::integral_type(input[i].data);
    }

    typename NonNativeFieldType::integral_type output_integral =
        input_integral[0] + (input_integral[1] << 66) + (input_integral[2] << 132) + (input_integral[3] << 198);

    typename NonNativeFieldType::value_type output = typename NonNativeFieldType::value_type(output_integral);

    return output;
}

template<typename FieldType, typename NonNativeFieldType>
std::vector<typename FieldType::value_type> create_public_input(std::array<typename FieldType::value_type, 4> a,
                                                                std::array<typename FieldType::value_type, 4> b) {
    std::vector<typename FieldType::value_type> public_input;
    for (std::size_t i = 0; i < a.size(); i++) {
        public_input.push_back(a[i]);
    }
    for (std::size_t i = 0; i < b.size(); i++) {
        public_input.push_back(b[i]);
    }
    return public_input;
}

template<typename FieldType, typename NonNativeFieldType>
std::vector<typename FieldType::value_type>
    create_public_input_1_value(std::array<typename FieldType::value_type, 4> b) {
    std::vector<typename FieldType::value_type> public_input;
    for (std::size_t i = 0; i < b.size(); i++) {
        public_input.push_back(b[i]);
    }
    return public_input;
}