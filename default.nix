{ pkgs ? import <nixpkgs> {} }:
pkgs.stdenv.mkDerivation {
  name = "run-in-fsns";
  src = ./src;
  makeFlags = [ "PREFIX=$(out)" ];
}
