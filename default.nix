{ pkgs ? import <nixpkgs> {} }:
pkgs.stdenv.mkDerivation {
  name = "run-in-fsns";
  src = pkgs.lib.cleanSource ./.;
  makeFlags = [ "PREFIX=$(out)" ];
}
