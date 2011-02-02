module Network.Protocol.SSH.ServerHostKey (Algorithm(..),
                                           knownAlgorithmNames,
                                           algorithmName,
                                           algorithmFromName,
                                           algorithmSupportsEncryption,
                                           algorithmSupportsSignatures,
                                           computeAlgorithm)
  where

import {-# SOURCE #-} qualified
  Network.Protocol.SSH.KeyExchange as KeyExchange


data Algorithm = Algorithm_SSH_DSS
               deriving (Eq)


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["ssh-dss"]


algorithmName :: Algorithm -> String
algorithmName Algorithm_SSH_DSS = "ssh-dss"


algorithmFromName :: String -> Maybe Algorithm
algorithmFromName "ssh-dss" = Just Algorithm_SSH_DSS
algorithmFromName _ = Nothing


algorithmSupportsEncryption :: Algorithm -> Bool
algorithmSupportsEncryption Algorithm_SSH_DSS = False


algorithmSupportsSignatures :: Algorithm -> Bool
algorithmSupportsSignatures Algorithm_SSH_DSS = True


computeAlgorithm :: KeyExchange.Algorithm
                 -> [Algorithm]
                 -> [Algorithm]
                 -> Maybe Algorithm
computeAlgorithm keyExchangeAlgorithm
                 clientAlgorithms
                 serverAlgorithms =
  let consider (algorithm:remainingAlgorithms) =
        if and [elem algorithm serverAlgorithms,
                or [not $ KeyExchange.algorithmRequiresEncryption
                           keyExchangeAlgorithm,
                    algorithmSupportsEncryption algorithm],
                or [not $ KeyExchange.algorithmRequiresSignatures
                           keyExchangeAlgorithm,
                    algorithmSupportsSignatures algorithm]]
          then Just algorithm
          else consider remainingAlgorithms
      consider [] = Nothing
  in consider clientAlgorithms
