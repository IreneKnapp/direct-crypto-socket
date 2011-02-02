module Network.Protocol.SSH.ServerHostKey (Algorithm(..),
                                           knownAlgorithmNames,
                                           algorithmName,
                                           algorithmFromName,
                                           algorithmSupportsEncryption,
                                           algorithmSupportsSignatures)
  where


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
