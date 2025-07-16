{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    android-nixpkgs = {
      url = "github:tadfisher/android-nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      android-nixpkgs,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };

      androidSdkFor =
        system:
        android-nixpkgs.sdk.${system} (
          sdkPkgs: with sdkPkgs; [
            cmdline-tools-latest
            ndk-27-1-12297006
            ndk-26-1-10909125
          ]
        );

      # macOS-specific derivations
      darwinDerivations = {
        xcode-wrapper =
          pkgs:
          pkgs.stdenv.mkDerivation {
            name = "xcode-wrapper-16.4.0";
            buildInputs = [ pkgs.darwin.cctools ];
            buildCommand = ''
              mkdir -p $out/bin

              # Create wrapper scripts instead of symlinks
              cat > $out/bin/xcodebuild << EOF
              #!/bin/sh
              exec /usr/bin/xcodebuild "\$@"
              EOF

              cat > $out/bin/xcrun << EOF
              #!/bin/sh
              exec /usr/bin/xcrun "\$@"
              EOF

              cat > $out/bin/xcode-select << EOF
              #!/bin/sh
              exec /usr/bin/xcode-select "\$@"
              EOF

              cat > $out/bin/codesign << EOF
              #!/bin/sh
              exec /usr/bin/codesign "\$@"
              EOF

              cat > $out/bin/ld << EOF
              #!/bin/sh
              exec /usr/bin/ld "\$@"
              EOF

              cat > $out/bin/clang << EOF
              #!/bin/sh
              exec /usr/bin/clang "\$@"
              EOF

              chmod +x $out/bin/*

              if [ -d "/Applications/Xcode.app" ]; then
                DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
              elif [ -d "/Applications/Xcode-16.4.0.app" ]; then
              DEVELOPER_DIR="/Applications/Xcode-16.4.0.app/Contents/Developer"
              else
                echo "Error: Xcode not found"
                exit 1
              fi

              echo "export DEVELOPER_DIR=\"$DEVELOPER_DIR\"" > $out/bin/env.sh
            '';
          };
        scripts = pkgs: {
          build-ios = pkgs.writeScriptBin "build-ios" ''
            #!${pkgs.stdenv.shell}
            echo "Building for iOS..."
            chmod +x ./build-ios.sh
            ./build-ios.sh
          '';

          build-macos = pkgs.writeScriptBin "build-macos" ''
            #!${pkgs.stdenv.shell}
            echo "Building for macOS..."
            chmod +x ./build-macos.sh
            ./build-macos.sh
          '';

          build-android = pkgs.writeScriptBin "build-android" ''
            #!${pkgs.stdenv.shell}
            echo "Building for Android..."
            chmod +x ./build-android.sh
            ./build-android.sh
          '';

          build-all = pkgs.writeScriptBin "build-all" ''
            #!${pkgs.stdenv.shell}
            echo "Building for Android..."
            chmod +x ./build-android.sh
            ./build-android.sh

            echo "Building for iOS..."
            chmod +x ./build-ios.sh
            ./build-ios.sh

            echo "Building for macOS..."
            chmod +x ./build-macos.sh
            ./build-macos.sh
          '';
        };
      };

      # System-specific shell configuration
      mkShellFor =
        system:
        let
          pkgs = pkgsFor system;
          androidSdk = androidSdkFor system;
          scripts = darwinDerivations.scripts pkgs;

          basePackages = with pkgs; [
            upx
            androidSdk
            autoconf
            automake
            libtool
            openssl
            rustup
          ];

          darwinPackages = with pkgs; [
            (darwinDerivations.xcode-wrapper pkgs)
            scripts.build-ios
            scripts.build-macos
            scripts.build-android
            scripts.build-all
          ];

          darwinHook = ''
            export LC_ALL=en_US.UTF-8
            export LANG=en_US.UTF-8

            unset SDKROOT

            rustup target add aarch64-linux-android x86_64-linux-android i686-linux-android
            rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

            if [ -f "${darwinDerivations.xcode-wrapper pkgs}/bin/env.sh" ]; then
              source "${darwinDerivations.xcode-wrapper pkgs}/bin/env.sh"
            fi

            export LD=/usr/bin/clang
            export LD_FOR_TARGET=/usr/bin/clang

            echo "iOS development environment:"
            echo "DEVELOPER_DIR: $DEVELOPER_DIR"
            xcodebuild -version
          '';

          linuxHook = ''
            export LC_ALL=en_US.UTF-8
            export LANG=en_US.UTF-8
            rustup target add aarch64-linux-android x86_64-linux-android i686-linux-android
          '';

        in
        pkgs.mkShellNoCC {
          buildInputs = if system == "aarch64-darwin" then basePackages ++ darwinPackages else basePackages;

          shellHook = if system == "aarch64-darwin" then darwinHook else linuxHook;
        };
    in
    {
      devShells = forAllSystems (system: {
        default = mkShellFor system;
      });
    };
}
