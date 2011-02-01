module Network.Protocol.SSH.ServerHostKey (Algorithm(..),
                                           knownAlgorithmNames)
  where


data Algorithm = Algorithm_SSH_DSS


knownAlgorithmNames :: [String]
knownAlgorithmNames = ["ssh-dss"]
