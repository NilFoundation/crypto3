{ lib,
  stdenv,
  src_repo,
  ninja,
  pkg-config,
  cmake,
  boost183,
  # We'll use boost183 by default, but you can override it
  boost_lib ? boost183,
  gdb,
  cmake_modules,
  crypto3,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "blueprint";

  src = src_repo;

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost_lib) else boost_lib) ];

  buildInputs = [cmake_modules crypto3];

  cmakeFlags =
  [
      (if runTests then "-DBUILD_TESTS=TRUE" else "")
      (if runTests then "-DCMAKE_ENABLE_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      (if enableDebug then "-DCMAKE_CXX_FLAGS=-ggdb" else "")
      (if enableDebug then "-DCMAKE_CXX_FLAGS=-O0" else "")
      "-G Ninja"
  ];

  doBuild = false;
  doCheck = runTests;
  dontInstall = true;

  buildPhase = ''
    echo "skip build"
  '';

  checkPhase = ''
    bash ../run_tests.sh
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Blueprint development environment!"
  '';
}
