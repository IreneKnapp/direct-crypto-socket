module Network.Protocol.SSH.MAC (Algorithm(..),
                                 knownAlgorithmNames,
                                 algorithmName,
                                 algorithmFromName,
                                 computeAlgorithm,
                                 algorithmCodeLength,
                                 algorithmComputeCode)
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word


data Algorithm = Algorithm_HMAC_SHA1
               | Algorithm_None
               deriving (Eq)


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["hmac-sha1"]


algorithmName :: Algorithm -> String
algorithmName Algorithm_HMAC_SHA1 = "hmac-sha1"
algorithmName Algorithm_None = "none"


algorithmFromName :: String -> Maybe Algorithm
algorithmFromName "hmac-sha1" = Just Algorithm_HMAC_SHA1
algorithmFromName "none" = Just Algorithm_None
algorithmFromName _ = Nothing


computeAlgorithm :: [Algorithm] -> [Algorithm] -> Maybe Algorithm
computeAlgorithm clientAlgorithms serverAlgorithms =
  let consider (algorithm:remainingAlgorithms) =
        if elem algorithm serverAlgorithms
          then Just algorithm
          else consider remainingAlgorithms
      consider [] = Nothing
  in consider clientAlgorithms


algorithmCodeLength :: Algorithm -> Int
algorithmCodeLength Algorithm_None = 0


algorithmComputeCode :: Algorithm -> Word32 -> ByteString -> ByteString
algorithmComputeCode Algorithm_None _ _ = BS.empty
