{
  description = "Electrum development shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs:
        let
          python = pkgs.python314;

          # Test-time deps that `pip install -e .` does NOT pull in
          pyEnv = python.withPackages (ps: with ps; [
            pip
            pytest
            cryptography
            pycryptodomex
            pyaes
            pyqt6
          ]);
        in
        {
          default = pkgs.mkShell {
            packages = [
              pyEnv
              # Toolchain to compile libsecp256k1 for the electrum_ecc wheel.
              pkgs.gcc
              pkgs.gnumake
              pkgs.autoconf
              pkgs.automake
              pkgs.libtool
              pkgs.pkg-config
            ];

            shellHook = ''
              # A venv layered on top of the nix python: `pip install -e .` installs
              # Electrum (editable) + its pure-python deps in here, while pytest /
              # PyQt6 / cryptography are inherited from nixpkgs via site-packages.
              if [ ! -e .venv/bin/python ]; then
                echo "flake: creating .venv (system-site-packages) with ${python.name}"
                ${pyEnv}/bin/python -m venv --system-site-packages .venv
              fi
              source .venv/bin/activate

              # Make bare `pytest` use THIS venv's python (which sees the editable
              # electrum install), rather than the nix env's pytest entry point.
              if [ ! -e .venv/bin/pytest ]; then
                printf '#!/usr/bin/env bash\nexec "$(dirname "$0")/python" -m pytest "$@"\n' > .venv/bin/pytest
                chmod +x .venv/bin/pytest
              fi

              echo "Electrum dev shell ready.  Now run:"
              echo "    pip install -e ."
              echo "    pytest tests -v"
            '';
          };
        });
    };
}
