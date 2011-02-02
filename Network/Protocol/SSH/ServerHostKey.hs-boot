module Network.Protocol.SSH.ServerHostKey (Algorithm(..),
                                           algorithmSupportsEncryption,
                                           algorithmSupportsSignatures)
  where

data Algorithm = Algorithm_SSH_DSS

algorithmSupportsEncryption :: Algorithm -> Bool
algorithmSupportsSignatures :: Algorithm -> Bool
