module Network.Protocol.SSH.Compression (Algorithm(..),
                                         knownAlgorithmNames)
  where


data Algorithm = Algorithm_None
               deriving (Eq)


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["none"]
