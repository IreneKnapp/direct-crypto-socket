module Network.Protocol.SSH.KeyExchange (Algorithm(..),
                                         knownAlgorithmNames,
                                         algorithmName,
                                         algorithmFromName,
                                         algorithmRequiresEncryption,
                                         algorithmRequiresSignatures,
                                         computeAlgorithm)
  where

import Network.Protocol.SSH.Types
import qualified Network.Protocol.SSH.ServerHostKey as ServerHostKey


data Algorithm = Algorithm_Diffie_Hellman_Group1_SHA1
               | Algorithm_Diffie_Hellman_Group14_SHA1
               deriving (Eq)


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["diffie-hellman-group14-sha1",
                       "diffie-hellman-group1-sha1"]


algorithmName :: Algorithm -> String
algorithmName Algorithm_Diffie_Hellman_Group1_SHA1
  = "diffie-hellman-group1-sha1"
algorithmName Algorithm_Diffie_Hellman_Group14_SHA1
  = "diffie-hellman-group14-sha1"


algorithmFromName :: String -> Maybe Algorithm
algorithmFromName "diffie-hellman-group1-sha1"
  = Just Algorithm_Diffie_Hellman_Group1_SHA1
algorithmFromName "diffie-hellman-group14-sha1"
  = Just Algorithm_Diffie_Hellman_Group14_SHA1
algorithmFromName _ = Nothing


algorithmRequiresEncryption :: Algorithm -> Bool
algorithmRequiresEncryption Algorithm_Diffie_Hellman_Group1_SHA1 = False
algorithmRequiresEncryption Algorithm_Diffie_Hellman_Group14_SHA1 = False


algorithmRequiresSignatures :: Algorithm -> Bool
algorithmRequiresSignatures Algorithm_Diffie_Hellman_Group1_SHA1 = True
algorithmRequiresSignatures Algorithm_Diffie_Hellman_Group14_SHA1 = True


computeAlgorithm :: [Algorithm]
                 -> [Algorithm]
                 -> [ServerHostKey.Algorithm]
                 -> [ServerHostKey.Algorithm]
                 -> Maybe Algorithm
computeAlgorithm clientKeyExchangeAlgorithms
                 serverKeyExchangeAlgorithms
                 clientHostKeyAlgorithms
                 serverHostKeyAlgorithms =
  let consider (algorithm:remainingAlgorithms) =
        if and [elem algorithm serverKeyExchangeAlgorithms,
                or [not $ algorithmRequiresEncryption algorithm,
                    any (\serverHostKeyAlgorithm ->
                           and [ServerHostKey.algorithmSupportsEncryption
                                 serverHostKeyAlgorithm,
                                elem serverHostKeyAlgorithm
                                     clientHostKeyAlgorithms])
                        serverHostKeyAlgorithms],
                or [not $ algorithmRequiresSignatures algorithm,
                    any (\serverHostKeyAlgorithm ->
                           and [ServerHostKey.algorithmSupportsSignatures
                                 serverHostKeyAlgorithm,
                                elem serverHostKeyAlgorithm
                                     clientHostKeyAlgorithms])
                        serverHostKeyAlgorithms]]
          then Just algorithm
          else consider remainingAlgorithms
      consider [] = Nothing
  in consider clientKeyExchangeAlgorithms
