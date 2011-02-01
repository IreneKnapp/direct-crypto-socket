module Network.Protocol.SSH.Encryption (Algorithm(..),
                                        knownAlgorithmNames)
  where


data Algorithm = Algorithm_3DES_CBC


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["3des-cbc"]
