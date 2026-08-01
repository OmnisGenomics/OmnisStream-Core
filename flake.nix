{
  description = "OmnisStream Core";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          version = "0.1.0";
          targetTriple = pkgs.stdenv.hostPlatform.config;
          specPin = builtins.readFile ./SPEC_PIN.txt;
          specRev = builtins.replaceStrings [ "\n" ] [ "" ] specPin;
          specSrc = pkgs.fetchgit {
            url = "https://github.com/OmnisGenomics/OmnisStream-Spec";
            rev = specRev;
            hash = "sha256-cmmF/ynZ2SX5pTxhiEF8UJLEzVmdZGkKQXwYtnXnKw0=";
          };
          installSpec = ''
            rm -rf spec/omnisstream-spec
            mkdir -p spec
            cp -R ${specSrc} spec/omnisstream-spec
            chmod -R u+w spec/omnisstream-spec
          '';

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          omnisstream-core = pkgs.rustPlatform.buildRustPackage {
            pname = "omnisstream-core";
            inherit version cargoLock;

            src = pkgs.lib.cleanSource ./.;

            cargoBuildFlags = [
              "-p"
              "omnisstream_cli"
              "-p"
              "omnisstream_bench"
              "-p"
              "omnisstream_ffi"
            ];

            postPatch = installSpec;

            installPhase = ''
              runHook preInstall

              install -Dm755 "target/${targetTriple}/release/omnisstream" "$out/bin/omnisstream"
              install -Dm755 "target/${targetTriple}/release/omnisstream_bench" "$out/bin/omnisstream_bench"
              install -Dm644 "target/${targetTriple}/release/libomnisstream_ffi.a" "$out/lib/libomnisstream_ffi.a"
              install -Dm644 include/omnisstream_ffi.h "$out/include/omnisstream_ffi.h"

              runHook postInstall
            '';

            doCheck = false;

            meta = {
              description = "Core libraries, CLI, FFI, and benchmark tools for OmnisStream";
              homepage = "https://github.com/OmnisGenomics/OmnisStream-Core";
              license = pkgs.lib.licenses.asl20;
              mainProgram = "omnisstream";
            };
          };

          release-archive = pkgs.runCommand "omnisstream-core-release-${version}" { nativeBuildInputs = [ pkgs.zip ]; } ''
            set -euo pipefail

            package_dir="$out/pkg-${targetTriple}"
            mkdir -p "$package_dir"

            cp ${omnisstream-core}/bin/omnisstream "$package_dir/omnisstream"
            cp ${omnisstream-core}/bin/omnisstream_bench "$package_dir/omnisstream_bench"
            cp ${omnisstream-core}/lib/libomnisstream_ffi.a "$package_dir/libomnisstream_ffi.a"
            cp ${omnisstream-core}/include/omnisstream_ffi.h "$package_dir/omnisstream_ffi.h"
            cp ${./SPEC_PIN.txt} "$package_dir/SPEC_PIN.txt"

            (
              cd "$package_dir"
              sha256sum * > SHA256SUMS
              zip -X "$out/omnisstream-v${version}-${targetTriple}.zip" *
            )

            (
              cd "$out"
              sha256sum *.zip > SHA256SUMS
            )
          '';
        in
        {
          default = omnisstream-core;
          inherit omnisstream-core release-archive;
        }
      );

      checks = forAllSystems (
        pkgs:
        let
          version = "0.1.0";
          specPin = builtins.readFile ./SPEC_PIN.txt;
          specRev = builtins.replaceStrings [ "\n" ] [ "" ] specPin;
          specSrc = pkgs.fetchgit {
            url = "https://github.com/OmnisGenomics/OmnisStream-Spec";
            rev = specRev;
            hash = "sha256-cmmF/ynZ2SX5pTxhiEF8UJLEzVmdZGkKQXwYtnXnKw0=";
          };
          installSpec = ''
            rm -rf spec/omnisstream-spec
            mkdir -p spec
            cp -R ${specSrc} spec/omnisstream-spec
            chmod -R u+w spec/omnisstream-spec
          '';
          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          commonNativeBuildInputs = [
            pkgs.bash
            pkgs.cargo
            pkgs.clippy
            pkgs.cmake
            pkgs.diffutils
            pkgs.gitMinimal
            pkgs.python3
            pkgs.rustc
            pkgs.rustfmt
          ];

          mkSimpleCheck =
            name: command:
            pkgs.stdenvNoCC.mkDerivation {
              pname = "omnisstream-core-${name}";
              inherit version;
              src = pkgs.lib.cleanSource ./.;
              nativeBuildInputs = commonNativeBuildInputs;
              dontConfigure = true;
              postPatch = installSpec;
              buildPhase = ''
                runHook preBuild
                ${command}
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p "$out"
                touch "$out/${name}"
              '';
            };

          mkCargoCheck =
            name: command:
            pkgs.rustPlatform.buildRustPackage {
              pname = "omnisstream-core-${name}";
              inherit version cargoLock;
              src = pkgs.lib.cleanSource ./.;
              nativeBuildInputs = commonNativeBuildInputs;
              cargoBuildFlags = [ ];
              postPatch = installSpec;
              buildPhase = ''
                runHook preBuild
                ${command}
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p "$out"
                touch "$out/${name}"
              '';
              doCheck = false;
            };
        in
        {
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          spec-pin = mkSimpleCheck "spec-pin" ''
            echo "SPEC_PIN.txt=$(cat SPEC_PIN.txt)"
            echo "spec=${specRev}"
            test "$(cat SPEC_PIN.txt)" = "${specRev}"
            test -f spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto
            test -f spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb
          '';
          fmt = mkSimpleCheck "fmt" "cargo fmt --all -- --check";
          clippy = mkCargoCheck "clippy" "cargo clippy --all-targets --all-features -- -D warnings";
          tests = mkCargoCheck "tests" "cargo test --all-features";
          spec-contract = mkCargoCheck "spec-contract" ''
            cargo run -p omnisstream_cli -- version | tee version.txt
            grep -Fx "spec_pin $(cat SPEC_PIN.txt)" version.txt
            cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb
            cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb
            cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb > /dev/null
            cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb > /dev/null

            tmp="$(mktemp -d)"
            cp -a spec/omnisstream-spec/test-vectors/vector-minimal "$tmp/vector-minimal"
            OMNIS_TMP="$tmp" python3 - <<'PY'
            import os
            import pathlib
            p = pathlib.Path(os.environ["OMNIS_TMP"]) / "vector-minimal" / "parts" / "part-0002.bin"
            b = p.read_bytes()
            p.write_bytes(bytes([b[0] ^ 0xFF]) + b[1:])
            PY
            set +e
            cargo run -p omnisstream_cli -- verify "$tmp/vector-minimal/manifest.pb"
            code="$?"
            set -e
            test "$code" -ne 0
          '';
          ffi-cpp-smoke = mkCargoCheck "ffi-cpp-smoke" ''
            cargo build -p omnisstream_ffi --release
            cp include/omnisstream_ffi.h expected-omnisstream_ffi.h
            cargo run -p omnisstream_ffi --features header-gen --bin omnisstream_ffi_header
            diff -u expected-omnisstream_ffi.h include/omnisstream_ffi.h
            cmake -S examples/cpp_smoke -B target/cpp_smoke -DCMAKE_BUILD_TYPE=Release
            cmake --build target/cpp_smoke -j "$NIX_BUILD_CORES"
            ./target/cpp_smoke/os_cpp_smoke
          '';
          bench-mini = mkCargoCheck "bench-mini" ''
            cargo run -p omnisstream_bench --release -- --preset ci --out bench.json
            python3 - <<'PY'
            import json

            with open("bench.json", "rb") as f:
              data = json.load(f)

            assert data["schema_version"] == 1
            for k in ["generated_unix_ms", "tool_version", "params", "results"]:
              assert k in data

            params = data["params"]
            for k in ["preset", "file_size_bytes", "part_size_bytes", "range_len_bytes", "range_ops", "seed"]:
              assert k in params

            results = data["results"]
            for k in ["ingest", "verify", "range_reads"]:
              assert k in results

            for name in ["ingest", "verify"]:
              s = results[name]
              for k in ["ok", "wall_seconds", "bytes", "bytes_per_sec", "parts"]:
                assert k in s

            rr = results["range_reads"]
            for k in ["ok", "wall_seconds", "ops", "ops_per_sec", "bytes", "bytes_per_sec"]:
              assert k in rr
            PY

            cargo run -p omnisstream_benchdiff -- bench.json bench.json --threshold-percent 0
            python3 - <<'PY'
            import json
            from pathlib import Path

            p = Path("bench.json")
            data = json.loads(p.read_text())
            data["results"]["ingest"]["bytes_per_sec"] = max(0.0, data["results"]["ingest"]["bytes_per_sec"] * 0.5)
            Path("bench_regress.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            PY
            set +e
            cargo run -p omnisstream_benchdiff -- bench.json bench_regress.json --threshold-percent 0
            code="$?"
            set -e
            test "$code" -ne 0
          '';
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.clippy
            pkgs.cmake
            pkgs.gitMinimal
            pkgs.python3
            pkgs.rustc
            pkgs.rustfmt
          ];
        };
      });
    };
}
