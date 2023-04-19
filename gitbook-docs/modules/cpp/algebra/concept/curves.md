# curves

{% hint style="warning" %}
This article is in progress
{% endhint %}

## curve

A `curve` is a policy intended to represent an elliptic curve of the form $$y^{2}=x^{3}+ax+b$$

#### Requirements

The type `X` satisfies `curve` if

Given

* `BaseFieldType`, the type named by `X::base_field_type`
* `ScalarFieldType`, the type named by `X::scalar_field_type`
* `GType`, the type named by `X::g1_type`

The following type members must be valid and have their specified effects

| Expression             | Type        | Requirements                               |
| ---------------------- | ----------- | ------------------------------------------ |
| `X::base_field_type`   | `FieldType` | `FieldType` type satisfies `field` concept |
| `X::scalar_field_type` | `FieldType` | `FieldType` type satisfies `field` concept |
| `X::`g1\_type          | `FieldType` | `FieldType` type satisfies `field` concept |

## curves group

TODO: Describe a curve group

#### Requirements

The type `X` satisfies `curve_group` if

Given

* `FieldType`, the type named by `X::`value\_type
* `FieldType`, the type named by `X::`value\_type
* `CurveType`, the type named by `X::curve_type`
