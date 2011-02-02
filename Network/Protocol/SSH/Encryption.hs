module Network.Protocol.SSH.Encryption (Algorithm(..),
                                        knownAlgorithmNames)
  where


data Algorithm = Algorithm_3DES_CBC
               deriving (Eq)


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["3des-cbc"]
