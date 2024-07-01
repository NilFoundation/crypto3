{ lib,
  stdenv,
  src_repo,
  ninja,
  pkg-config,
  cmake,
  boost183,
  # We'll use boost183 by default, but you can override it
  boost_lib ? boost183,
  cmake_modules,
  enableDebugging,
  enableDebug ? false
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Crypto3";

  src = src_repo;

  nativeBuildInputs = [ cmake ninja pkg-config ];

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost_lib) else boost_lib) ];

  buildInputs = [cmake_modules];

  cmakeFlags =
    [ "-B build" "-G Ninja" "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}" ];

  dontBuild = true; # nothing to build, header-only lib

  doCheck = false; # tests are inside crypto3-tests derivation

  installPhase = ''
    cmake --build build --target install
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Crypto3 development environment!"
  '';
}
