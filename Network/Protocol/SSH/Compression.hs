module Network.Protocol.SSH.Compression (Algorithm(..),
                                         knownAlgorithmNames)
  where


data Algorithm = Algorithm_None


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["none"]
