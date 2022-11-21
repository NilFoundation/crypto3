# field

{% hint style="warning" %}
This article is in progress
{% endhint %}

##

## field

A `field` is a generic type to represent element in finite field.

#### Requirements

The type `X` satisfies `field` if

Given

* `ValueType`, the type named by `X::value_type`
* `IntegralType`, the type named by `X::integral_type`
* `ModularType`, the type named by `X::modular_type`

The following type members must be valid and have their specified effects

| Expression         | Type           | Requirements                                                     |
| ------------------ | -------------- | ---------------------------------------------------------------- |
| `X::value_type`    | `ValueType`    | TODO                                                             |
| `X::integral_type` | `IntegralType` | `IntegralType` is of type `nil::crypto3::multiprecision::number` |
| `X::modular_type`  | `ModularType`  | `ModularType` is of type `nil::crypto3::multiprecision::number`  |
