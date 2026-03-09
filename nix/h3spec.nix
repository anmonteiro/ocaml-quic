{ pkgs }:

pkgs.haskellPackages.override {
  overrides =
    self: super:
    let
      quicPatched = pkgs.haskell.lib.overrideCabal
        (pkgs.haskell.lib.doJailbreak (
          self.callHackageDirect {
            pkg = "quic";
            ver = "0.2.21";
            sha256 = "sha256-vM6qu8U/cZSdmVlOrp+ffZOEg2Jcv001S/SvKyispVI=";
          } { }
        ))
        (_: {
          postPatch = ''
            substituteInPlace Network/QUIC/Types/CID.hs \
              --replace-fail "import System.Random (getStdRandom, uniformByteString)" "" \
              --replace-fail "salt <- getStdRandom $ uniformByteString 20" "salt <- Short.fromShort <$> getRandomBytes 20" \
              --replace-fail "ikm <- getStdRandom $ uniformByteString 20" "ikm <- Short.fromShort <$> getRandomBytes 20"

            substituteInPlace Network/QUIC/Server/Reader.hs \
              --replace-fail "import System.Random (getStdRandom, randomRIO, uniformByteString)" "import System.Random (randomRIO)" \
              --replace-fail "body <- getStdRandom $ uniformByteString 1263" "let body = BS.replicate 1263 0"

            substituteInPlace Network/QUIC/Config.hs \
              --replace-fail "ccKeyLog = defaultKeyLogger" "ccKeyLog = const (return ())" \
              --replace-fail "scKeyLog = defaultKeyLogger" "scKeyLog = const (return ())"
          '';
        });
    in
    {
      http-semantics = super.http-semantics_0_4_0;
      http2 = super.http2_5_4_0.override {
        network-run = self.network-run_0_5_0;
      };
      quic = quicPatched;
      http3 = super.http3.override {
        quic = self.quic;
        http-semantics = self.http-semantics;
        http2 = self.http2;
      };
      h3spec = pkgs.haskell.lib.overrideCabal
        (super.h3spec.override {
          quic = self.quic;
          http3 = self.http3;
        })
        (_: {
          postPatch = ''
            substituteInPlace h3spec.hs \
              --replace-fail "h3cc = H3.ClientConfig \"https\" host" "h3cc = H3.defaultClientConfig { H3.scheme = \"https\", H3.authority = host }"
          '';
        });
    };
}
