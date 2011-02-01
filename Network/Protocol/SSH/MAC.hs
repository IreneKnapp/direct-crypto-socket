module Network.Protocol.SSH.MAC (Algorithm(..),
                                 algorithmCodeLength,
                                 algorithmComputeCode)
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word


data Algorithm = None


algorithmCodeLength :: Algorithm -> Int
algorithmCodeLength None = 0


algorithmComputeCode :: Algorithm -> Word32 -> ByteString -> ByteString
algorithmComputeCode None _ _ = BS.empty
