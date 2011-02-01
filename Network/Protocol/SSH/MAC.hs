module Network.Protocol.SSH.MAC (Algorithm(..),
                                 knownAlgorithmNames,
                                 algorithmCodeLength,
                                 algorithmComputeCode)
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word


data Algorithm = Algorithm_HMAC_SHA1
               | Algorithm_None


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["hmac-sha1", "none"]


algorithmCodeLength :: Algorithm -> Int
algorithmCodeLength Algorithm_None = 0


algorithmComputeCode :: Algorithm -> Word32 -> ByteString -> ByteString
algorithmComputeCode Algorithm_None _ _ = BS.empty
