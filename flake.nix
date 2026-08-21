{
  description = "Electrum development shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      # Vendored atheris (not yet in nixpkgs) needs clang + libFuzzer.
      atherisOverlay = final: prev: {
        python314 = prev.python314.override {
          packageOverrides = pyFinal: pyPrev: {
            atheris = pyFinal.callPackage ./nix/atheris.nix {
              stdenv = final.clangStdenv;
            };
          };
        };
      };

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs {
        inherit system;
        overlays = [ atherisOverlay ];
      }));

      # coverage.py cannot trace while atheris is importable, so the coverage
      # shell omits it and uses a separate venv (a shared venv would leak it).
      mkDevShell = pkgs: { withAtheris, venvDir }:
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
            coverage
          ] ++ pkgs.lib.optionals (withAtheris && pkgs.stdenv.hostPlatform.isLinux) [ ps.atheris ]);
        in
        pkgs.mkShell {
          packages = [
            pyEnv
            pkgs.gcc
            pkgs.gnumake
            pkgs.autoconf
            pkgs.automake
            pkgs.libtool
            pkgs.pkg-config
          ];

          shellHook = ''
            if [ ! -e ${venvDir}/bin/python ]; then
              echo "flake: creating ${venvDir} (system-site-packages) with ${python.name}"
              ${pyEnv}/bin/python -m venv --system-site-packages ${venvDir}
            fi
            source ${venvDir}/bin/activate

            # Shims so bare `pytest` / `coverage` use THIS venv's python (which
            # sees the editable electrum install), not nix env entry points.
            for tool in pytest coverage; do
              if [ ! -e ${venvDir}/bin/$tool ]; then
                printf '#!/usr/bin/env bash\nexec "$(dirname "$0")/python" -m '"$tool"' "$@"\n' > ${venvDir}/bin/$tool
                chmod +x ${venvDir}/bin/$tool
              fi
            done

            pip install -e .

            echo "Electrum dev shell ready."
            echo "  Tests: pytest tests/ [-k <expr>]"
          '' + (if withAtheris then ''
            echo "  Fuzz:  python tests/fuzz/fuzz_<harness>.py <corpus>"
          '' else ''
            echo "  Coverage (atheris-free shell):"
            echo "    coverage run --include='*/electrum/<module>.py' tests/fuzz/fuzz_<harness>.py"
            echo "    coverage report"
          '');
        };
    in
    {
      devShells = forAllSystems (pkgs: {
        default = mkDevShell pkgs { withAtheris = true; venvDir = ".venv"; };
        coverage = mkDevShell pkgs { withAtheris = false; venvDir = ".venv-coverage"; };
      });
    };
}
