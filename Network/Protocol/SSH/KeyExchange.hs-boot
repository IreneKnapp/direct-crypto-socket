module Network.Protocol.SSH.KeyExchange (Algorithm(..),
                                         algorithmRequiresEncryption,
                                         algorithmRequiresSignatures)
  where


data Algorithm = Algorithm_Diffie_Hellman_Group1_SHA1
               | Algorithm_Diffie_Hellman_Group14_SHA1

algorithmRequiresEncryption :: Algorithm -> Bool
algorithmRequiresSignatures :: Algorithm -> Bool
