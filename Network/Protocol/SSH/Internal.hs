module Network.Protocol.SSH.Internal (
                                      streamReadWord32,
                                      streamReadWord8,
                                      packWord32,
                                      packWord8,
                                      packNameList,
                                      packString,
                                      packBinaryString,
                                      packBoolean,
                                      unpackRaw,
                                      unpackWord32,
                                      unpackWord8,
                                      unpackNameList,
                                      unpackString,
                                      unpackBinaryString,
                                      unpackBoolean
                                     )
  where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.List as L
import Data.Word

import Internal.AbstractStreams


streamReadWord32 :: AbstractStream -> IO (Maybe Word32)
streamReadWord32 stream = do
  maybeBytestring <- streamRead stream 4
  case maybeBytestring of
    Nothing -> return Nothing
    Just bytestring -> let (result, _) = unpackWord32 bytestring
                       in return result


streamReadWord8 :: AbstractStream -> IO (Maybe Word8)
streamReadWord8 stream = do
  maybeBytestring <- streamRead stream 1
  case maybeBytestring of
    Nothing -> return Nothing
    Just bytestring -> let (result, _) = unpackWord8 bytestring
                       in return result


packWord32 :: Word32 -> ByteString
packWord32 word = BS.pack [fromIntegral $ shiftR word 24,
                           fromIntegral $ shiftR word 16,
                           fromIntegral $ shiftR word 8,
                           fromIntegral $ shiftR word 0]


packWord8 :: Word8 -> ByteString
packWord8 word = BS.pack [fromIntegral $ shiftR word 0]


packNameList :: [String] -> ByteString
packNameList nameList =
  packString $ L.intercalate "," nameList


packString :: String -> ByteString
packString string =
  packBinaryString $ UTF8.fromString string


packBinaryString :: ByteString -> ByteString
packBinaryString bytestring =
  BS.concat [packWord32 $ fromIntegral $ BS.length bytestring,
             bytestring]


packBoolean :: Bool -> ByteString
packBoolean boolean =
  packWord8 $ case boolean of
                False -> 0
                True -> 1


unpackRaw :: Int -> ByteString -> (Maybe ByteString, ByteString)
unpackRaw size bytestring =
  let consumedPortion = BS.take size bytestring
      rest = BS.drop size bytestring
      maybeResult =
        if BS.length consumedPortion == size
           then Just consumedPortion
           else Nothing
  in (maybeResult, rest)


unpackWord32 :: ByteString -> (Maybe Word32, ByteString)
unpackWord32 bytestring =
  let consumedPortion = BS.take 4 bytestring
      rest = BS.drop 4 bytestring
      maybeResult =
        if BS.length consumedPortion == 4
          then let [a1, a2, a3, a4] = BS.unpack consumedPortion
               in Just $ shiftL (fromIntegral a1) 24
                         + shiftL (fromIntegral a2) 16
                         + shiftL (fromIntegral a3) 8
                         + shiftL (fromIntegral a4) 0
          else Nothing
  in (maybeResult, rest)


unpackWord8 :: ByteString -> (Maybe Word8, ByteString)
unpackWord8 bytestring =
  let consumedPortion = BS.take 1 bytestring
      rest = BS.drop 1 bytestring
      maybeResult =
        if BS.length consumedPortion == 1
          then let [a1] = BS.unpack consumedPortion
               in Just $ shiftL (fromIntegral a1) 0
          else Nothing
  in (maybeResult, rest)


unpackNameList :: ByteString -> (Maybe [String], ByteString)
unpackNameList bytestring =
  let (maybeString, remainingBytestring) = unpackString bytestring
      maybeResults = fmap (\string -> loop [] string) maybeString
      loop results string =
             case L.elemIndex ',' string of
               Nothing -> results ++ [string]
               Just index -> loop (results ++ [take index string])
                                  (drop (index + 1) string)
  in (maybeResults, remainingBytestring)


unpackString :: ByteString -> (Maybe String, ByteString)
unpackString bytestring =
  let (maybeBinaryString, bytestring') = unpackBinaryString bytestring
      maybeString = fmap UTF8.toString maybeBinaryString
  in (maybeString, bytestring')


unpackBinaryString :: ByteString -> (Maybe ByteString, ByteString)
unpackBinaryString bytestring =
  let (maybeSize, bytestring') = unpackWord32 bytestring
  in case maybeSize of
       Nothing -> (Nothing, bytestring')
       Just size -> unpackRaw (fromIntegral size) bytestring'


unpackBoolean :: ByteString -> (Maybe Bool, ByteString)
unpackBoolean bytestring =
  let (maybeValue, bytestring') = unpackWord8 bytestring
      maybeResult = fmap (\value -> case value of
                                      0 -> False
                                      _ -> True)
                         maybeValue
  in (maybeResult, bytestring')
