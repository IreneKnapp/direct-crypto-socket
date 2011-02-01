module Network.Protocol.SSH.KeyExchange (Algorithm(..),
                                         knownAlgorithmNames)
  where


data Algorithm = Algorithm_Diffie_Hellman_Group1_SHA1
               | Algorithm_Diffie_Hellman_Group14_SHA1

knownAlgorithmNames :: [String]
knownAlgorithmNames = ["diffie-hellman-group14-sha1",
                       "diffie-hellman-group1-sha1"]
