{
  description = "A deterministic, purely functional simulation of a POSIX process.";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
  # flake-utils' default systems less x86_64-darwin, whose support nixpkgs dropped
  # in 26.11: from then on, evaluating anything for it fails.
    flake-utils.lib.eachSystem ["aarch64-darwin" "aarch64-linux" "x86_64-linux"] (system: let
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };
      pname = "WoofWare.PosixKernel";
      # The library targets net8.0 and the tests net10.0; the .NET 10 SDK builds both, and
      # the .NET 10 runtime is the only one the test host needs.
      dotnet-sdk = pkgs.dotnetCorePackages.sdk_10_0;
      dotnet-runtime = pkgs.dotnetCorePackages.runtime_10_0;
      version = "0.1";
      dotnetTool = dllOverride: toolName: toolVersion: hash:
        pkgs.stdenvNoCC.mkDerivation rec {
          name = toolName;
          version = toolVersion;
          nativeBuildInputs = [pkgs.makeWrapper];
          src = pkgs.fetchNuGet {
            pname = name;
            version = version;
            hash = hash;
            installPhase = ''mkdir -p $out/bin && cp -r tools/net*/any/* $out/bin'';
          };
          installPhase = let
            dll =
              if isNull dllOverride
              then name
              else dllOverride;
          in ''
            runHook preInstall
            mkdir -p "$out/lib"
            cp -r ./bin/* "$out/lib"
            makeWrapper "${dotnet-sdk}/bin/dotnet" "$out/bin/${name}" --set DOTNET_HOST_PATH "${dotnet-sdk}/bin/dotnet" --add-flags "$out/lib/${dll}.dll"
            runHook postInstall
          '';
        };
      # The library's .fs files, without build output, as the prose checks read them.
      librarySources = pkgs.lib.fileset.toSource {
        root = ./WoofWare.PosixKernel;
        fileset = pkgs.lib.fileset.fileFilter (f: f.hasExt "fs") ./WoofWare.PosixKernel;
      };
      # The test project's .fs files, without build output, as the test-boundaries check reads them.
      testSources = pkgs.lib.fileset.toSource {
        root = ./WoofWare.PosixKernel.Test;
        fileset = pkgs.lib.fileset.fileFilter (f: f.hasExt "fs") ./WoofWare.PosixKernel.Test;
      };
    in {
      packages = let
        deps = builtins.fromJSON (builtins.readFile ./nix/deps.json);
      in {
        fantomas = dotnetTool null "fantomas" (builtins.fromJSON (builtins.readFile ./.config/dotnet-tools.json)).tools.fantomas.version (builtins.head (builtins.filter (elem: elem.pname == "fantomas") deps)).hash;
        default = pkgs.buildDotnetModule {
          inherit pname version dotnet-sdk dotnet-runtime;
          name = "WoofWare.PosixKernel";
          src = ./.;
          projectFile = "./WoofWare.PosixKernel/WoofWare.PosixKernel.fsproj";
          nugetDeps = ./nix/deps.json; # `nix build .#default.fetch-deps && ./result nix/deps.json`
          # The tests run in CI's `build` job, under `nix develop`. Several of them compare the
          # library with the real kernel running them (`*AgainstHost`), and the build sandbox
          # is a different kernel environment: on Linux its seccomp filter refuses set-ID modes
          # to chmod, and it has no python3, which one of those tests starts. So this package
          # builds the library and leaves the tests to the devshell.
          doCheck = false;
        };
      };
      checks = {
        # Fails `nix flake check` when a WoofWare.PosixKernel source line names a client
        # (WoofWare.PawPrint or one of its symbols, CoreCLR or its PAL) or calls the process a
        # guest. The library is meant to read as a POSIX simulator that knows nothing of any
        # client, and prose is where that knowledge creeps in. Runs the checker's own contract
        # first, so that a change to the checker cannot quietly retire it.
        client-references =
          pkgs.runCommand "client-references" {
            buildInputs = [pkgs.python3 pkgs.bash];
          }
          ''
            ${pkgs.bash}/bin/bash ${./scripts/test-client-references.sh} \
              ${./scripts/check-client-references.py}
            ${pkgs.python3}/bin/python3 ${./scripts/check-client-references.py} ${librarySources}
            touch $out
          '';
        # Fails `nix flake check` when a test file outside a rule's allowlist names a kernel
        # internal that the test helpers hide: the thread table, which tests read through `Proc`
        # and `Lone` and forge through `ForgedThread`; the process table, views and
        # `UnixSystemState`, behind `Proc` and `Lone`; and the `UnixSystem` record's machine and
        # scheduling, behind `Kernel` and the public queries. A test holding the representation must
        # change whenever it does, though nothing the test asserts has. Runs the checker's own
        # contract first, so that a change to the checker cannot quietly retire it.
        test-boundaries =
          pkgs.runCommand "test-boundaries" {
            buildInputs = [pkgs.python3 pkgs.bash];
          }
          ''
            ${pkgs.bash}/bin/bash ${./scripts/test-test-boundaries.sh} \
              ${./scripts/check-test-boundaries.py}
            ${pkgs.python3}/bin/python3 ${./scripts/check-test-boundaries.py} ${testSources}
            touch $out
          '';
        # The docstring-attachment check is the oracle a definition-moving commit is held
        # to, and it is only as good as its own contract: thirty-six shapes in a throwaway
        # repository, eighteen of which must be reported and eighteen of which must not. The
        # wrapper CI runs has a contract of its own, that it never passes without having
        # compared anything. Runs here so that a change to either cannot quietly retire it.
        docstring-attachment =
          pkgs.runCommand "docstring-attachment" {
            buildInputs = [pkgs.python3 pkgs.git pkgs.bash];
          }
          ''
            export HOME=$TMPDIR
            ${pkgs.bash}/bin/bash ${./scripts/test-docstring-attachment.sh} \
              ${./scripts/check-docstring-attachment.py}
            ${pkgs.bash}/bin/bash ${./scripts/test-docstring-attachment-branch.sh} \
              ${./scripts/check-docstring-attachment-branch.sh} \
              ${./scripts/check-docstring-attachment.py}
            touch $out
          '';
      };
      devShells.default = pkgs.mkShell {
        buildInputs = [dotnet-sdk];
        DOTNET_CLI_TELEMETRY_OPTOUT = "1";
        # mkShell's stdenv puts `cc` on the path. TestSignalFuzz builds its harness with it,
        # and fails rather than skips when this says a compiler was promised.
        POSIXKERNEL_REQUIRE_C_COMPILER = "1";
        # Likewise for the python3 in `packages` below, which
        # TestVirtualFileSystemAgainstHost starts.
        POSIXKERNEL_REQUIRE_PYTHON3 = "1";
        packages = [
          pkgs.alejandra
          pkgs.shellcheck
          pkgs.xmlstarlet
          # `docs/probes/**/*.py` are run by hand from this shell, and
          # `TestVirtualFileSystemAgainstHost` spawns it: a working directory is
          # process-global, so the host half of the `chdir` comparison cannot run
          # in the test host, and Python is the only thing to hand that reports
          # errno numerically. Declared here rather than relied on from the
          # ambient system, so that CI -- which runs `nix develop --command
          # dotnet test` -- runs that comparison instead of skipping it, and
          # POSIXKERNEL_REQUIRE_PYTHON3 above fails it if python3 is missing.
          pkgs.python3
        ];
      };
    });
}
