module Network.Protocol.SSH.Internal (
                                      streamSendNameList,
                                      streamSendString,
                                      streamSendBinaryString,
                                      streamSendBoolean,
                                      streamReadNameList,
                                      streamReadString,
                                      streamReadBinaryString,
                                      streamReadBoolean
                                     )
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.List as L
import Data.Word

import Internal.AbstractStreams


streamSendNameList :: AbstractStream -> [String] -> IO ()
streamSendNameList stream nameList = do
  streamSendString stream $ L.intercalate "," nameList


streamSendString :: AbstractStream -> String -> IO ()
streamSendString stream string = do
  streamSendBinaryString stream $ UTF8.fromString string


streamSendBinaryString :: AbstractStream -> ByteString -> IO ()
streamSendBinaryString stream bytestring = do
  streamSendWord32 stream $ fromIntegral $ BS.length bytestring
  streamSend stream bytestring


streamSendBoolean :: AbstractStream -> Bool -> IO ()
streamSendBoolean stream boolean = do
  streamSendWord8 stream $ case boolean of
                             False -> 0
                             True -> 1


streamReadNameList :: AbstractStream -> IO (Maybe [String])
streamReadNameList stream = do
  maybeString <- streamReadString stream
  case maybeString of
    Nothing -> return Nothing
    Just string -> do
      return $ Just $ loop [] string
      where loop results string =
              case L.elemIndex ',' string of
                Nothing -> results ++ [string]
                Just index -> loop (results ++ [take index string])
                                   (drop (index + 1) string)


streamReadString :: AbstractStream -> IO (Maybe String)
streamReadString stream = do
  maybeLength <- streamReadWord32 stream
  case maybeLength of
    Nothing -> return Nothing
    Just length -> do
      maybePayload <- streamRead stream $ fromIntegral length
      case maybePayload of
        Nothing -> return Nothing
        Just payload -> return $ Just $ UTF8.toString payload


streamReadBinaryString :: AbstractStream -> IO (Maybe ByteString)
streamReadBinaryString stream = do
  maybeLength <- streamReadWord32 stream
  case maybeLength of
    Nothing -> return Nothing
    Just length -> streamRead stream $ fromIntegral length


streamReadBoolean :: AbstractStream -> IO (Maybe Bool)
streamReadBoolean stream = do
  maybeValue <- streamReadWord8 stream
  case maybeValue of
    Nothing -> return Nothing
    Just 0 -> return $ Just False
    Just _ -> return $ Just True
