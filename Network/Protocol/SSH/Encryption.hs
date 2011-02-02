module Network.Protocol.SSH.Encryption (Algorithm(..),
                                        knownAlgorithmNames,
                                        algorithmName,
                                        algorithmFromName,
                                        computeAlgorithm)
  where


data Algorithm = Algorithm_3DES_CBC
               deriving (Eq)


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["3des-cbc"]


algorithmName :: Algorithm -> String
algorithmName Algorithm_3DES_CBC = "3des-cbc"


algorithmFromName :: String -> Maybe Algorithm
algorithmFromName "3des-cbc" = Just Algorithm_3DES_CBC
algorithmFromName _ = Nothing


computeAlgorithm :: [Algorithm] -> [Algorithm] -> Maybe Algorithm
computeAlgorithm clientAlgorithms serverAlgorithms =
  let consider (algorithm:remainingAlgorithms) =
        if elem algorithm serverAlgorithms
          then Just algorithm
          else consider remainingAlgorithms
      consider [] = Nothing
  in consider clientAlgorithms
