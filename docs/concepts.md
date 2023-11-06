# Concepts # {#component_concepts}

A ```circuit``` is defined by ```Blueprint``` and ```Blueprint assignment table``` (contains ```Blueprint public assignment table``` and ```Blueprint private assignment table```) instances.
It consist of one or multiple components putted on these two.
While ```Blueprint``` holds information about the circuit itself, its gates, constraints and other fixed expressions, ```Blueprint assignment table``` contains public and private assignments needed by zk-SNARK system.

## Blueprint 

## PLONK component concept ## {##plonk_component_concepts}

### PLONK Component interface ###

A ```Component``` ```X``` is a state-less type with following static functions to operate with it:

* ```X::allocate_rows``` - allocates required amount of rows in the given ```Arithmetization table```. The amount of required rows amount is constexpr for the particular component;
* ```X::generate_circuit``` - generates gate expressions, copy constraints and lookup constraints and puts them on the given ```Blueprint```;
* ```X::generate_assignments``` - evaluates assignments values and puts them on the given ```Blueprint assignment table```;

Note that ```generate_circuit``` can modify of the ```Blueprint public assignment table``` setting ```Constant``` or ```Selector``` columns, but they don't use or set data of the ```Blueprint private assignment table```. The only function managing ```Blueprint private assignment table``` is ```generate_assignments``` - which, by the way, also can modify the ```Blueprint public assignment table```. In short, it looks like that:

|Function                   |Required Input                    |Can modify |
|-----------------------------|------------------------|-----------------------|
|```X::allocate_rows```       |```Blueprint```         |```Blueprint```|
|```X::generate_circuit```      |```Blueprint```, ```Component params```, ```Allocated data (auxiliary data for the component re-use)```, ```component start row```          |```Blueprint```, ```Allocated data```|
|```X::generate_assignments```  |```Blueprint assignment table```, ```Component params```, ```component start row```        |```Blueprint assignment table```|

The process of adding a component is following:

1. (Optional) Get ```component``` start row by calling ```allocate_rows```. If the ```component``` is used as part of other ```component``` logic, it's not necessary to call the function, because needed rows are allocated by the master ```component```.
2. (Optional) Allocate public input on the ```Blueprint assignment table``` via ```Blueprint assignment table::allocate_public_input```.
3. Set all the gates and constraints on the ```Blueprint``` by calling ```generate_circuit```. ```Allocated data``` is being modified in process of the function working.
4. Set all the assignments on the ```Blueprint assignment table``` table by calling ```generate_assignments```.