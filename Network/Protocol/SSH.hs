module Network.Protocol.SSH (
                             startSSH,
                             streamReadSSHMessage
                            )
  where

import Control.Concurrent.MVar
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.List as L
import Data.Maybe
import Data.Word

import Internal.AbstractStreams
import qualified Network.Protocol.SSH.MAC as MAC


data SSHStream = SSHStream {
    sshStreamUnderlyingStream :: AbstractStream,
    sshStreamOpen :: MVar Bool,
    sshStreamSendMACAlgorithm :: MVar MAC.Algorithm,
    sshStreamSendSequenceNumber :: MVar Word32,
    sshStreamRecvMACAlgorithm :: MVar MAC.Algorithm,
    sshStreamRecvSequenceNumber :: MVar Word32
  }


data SSHMessage
  = SSHMessageKeyExchangeInit {
      sshMessageCookie :: ByteString,
      sshMessageKeyExchangeAlgorithms :: [String],
      sshMessageServerHostKeyAlgorithms :: [String],
      sshMessageEncryptionAlgorithmsClientToServer :: [String],
      sshMessageEncryptionAlgorithmsServerToClient :: [String],
      sshMessageMACAlgorithmsClientToServer :: [String],
      sshMessageMACAlgorithmsServerToClient :: [String],
      sshMessageCompressionAlgorithmsClientToServer :: [String],
      sshMessageCompressionAlgorithmsServerToClient :: [String],
      sshMessageLanguagesClientToServer :: [String],
      sshMessageLanguagesServerToClient :: [String],
      sshMessageFirstKeyExchangePacketFollows :: Bool
    }
  deriving (Show)


startSSH :: AbstractStream -> IO AbstractStream
startSSH underlyingStream = do
  openMVar <- newMVar True
  sendSequenceNumberMVar <- newMVar 0
  sendMACAlgorithmMVar <- newMVar MAC.None
  recvSequenceNumberMVar <- newMVar 0
  recvMACAlgorithmMVar <- newMVar MAC.None
  let sshStream = SSHStream {
                    sshStreamUnderlyingStream = underlyingStream,
                    sshStreamOpen = openMVar,
                    sshStreamSendSequenceNumber = sendSequenceNumberMVar,
                    sshStreamSendMACAlgorithm = sendMACAlgorithmMVar,
                    sshStreamRecvSequenceNumber = recvSequenceNumberMVar,
                    sshStreamRecvMACAlgorithm = recvMACAlgorithmMVar
                  }
  return $ AbstractStream {
             streamSend = sshStreamSend sshStream,
             streamRead = sshStreamRead sshStream,
             streamClose = sshStreamClose sshStream
           }


sshStreamSend :: SSHStream -> ByteString -> IO ()
sshStreamSend sshStream bytestring = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  macAlgorithm <- readMVar $ sshStreamSendMACAlgorithm sshStream
  sequenceNumber <- takeMVar $ sshStreamSendSequenceNumber sshStream
  putMVar (sshStreamSendSequenceNumber sshStream) $ sequenceNumber + 1


sshStreamRead :: SSHStream -> Int -> IO (Maybe ByteString)
sshStreamRead sshStream count = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  let stream = sshStreamUnderlyingStream sshStream
  macAlgorithm <- readMVar $ sshStreamRecvMACAlgorithm sshStream
  sequenceNumber <- takeMVar $ sshStreamRecvSequenceNumber sshStream
  putMVar (sshStreamRecvSequenceNumber sshStream) $ sequenceNumber + 1
  maybePacketLength <- streamReadWord32 stream
  case maybePacketLength of
    Nothing -> return Nothing
    Just packetLength -> do
      maybePaddingLength <- streamReadWord8 stream
      case maybePaddingLength of
        Nothing -> return Nothing
        Just paddingLength -> do
          maybePayload
            <- streamRead stream
                $ fromIntegral $ packetLength - (fromIntegral paddingLength) - 1
          case maybePayload of
            Nothing -> return Nothing
            Just payload -> do
              maybePadding
                <- streamRead stream $ fromIntegral paddingLength
              case maybePadding of
                Nothing -> return Nothing
                Just _ -> do
                  let macLength = MAC.algorithmCodeLength macAlgorithm
                  maybeMAC <- streamRead stream macLength
                  case maybeMAC of
                    Nothing -> return Nothing
                    Just mac -> do
                      let correctMAC =
                            MAC.algorithmComputeCode macAlgorithm
                                                     sequenceNumber
                                                     payload
                      if mac == correctMAC
                        then return $ Just payload
                        else do
                          _ <- takeMVar $ sshStreamOpen sshStream
                          streamClose stream
                          putMVar (sshStreamOpen sshStream) False
                          return Nothing


sshStreamClose :: SSHStream -> IO ()
sshStreamClose sshStream = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  streamClose $ sshStreamUnderlyingStream sshStream


streamReadSSHMessage :: AbstractStream -> IO (Maybe SSHMessage)
streamReadSSHMessage stream = do
  maybeMessageType <- streamReadWord8 stream
  case maybeMessageType of
    Nothing -> error "Incoming SSH stream unexpectedly ended."
    Just 1 -> return Nothing -- Disconnect
    Just 2 -> return Nothing -- Ignore
    Just 3 -> return Nothing -- Unimplemented
    Just 4 -> return Nothing -- Debug
    Just 5 -> return Nothing -- Service request
    Just 6 -> return Nothing -- Service accept
    Just 20 -> do
      maybeCookie <- streamRead stream 16
      maybeKeyExchangeAlgorithms <- streamReadNameList stream
      maybeServerHostKeyAlgorithms <- streamReadNameList stream
      maybeEncryptionAlgorithmsClientToServer <- streamReadNameList stream
      maybeEncryptionAlgorithmsServerToClient <- streamReadNameList stream
      maybeMACAlgorithmsClientToServer <- streamReadNameList stream
      maybeMACAlgorithmsServerToClient <- streamReadNameList stream
      maybeCompressionAlgorithmsClientToServer <- streamReadNameList stream
      maybeCompressionAlgorithmsServerToClient <- streamReadNameList stream
      maybeLanguagesClientToServer <- streamReadNameList stream
      maybeLanguagesServerToClient <- streamReadNameList stream
      maybeFirstKeyExchangePacketFollows <- streamReadBoolean stream
      maybePadding <- streamReadWord32 stream
      case maybePadding of
        Nothing -> return Nothing
        Just _ -> 
          return $ Just
                 SSHMessageKeyExchangeInit {
                     sshMessageCookie
                       = fromJust maybeCookie,
                     sshMessageKeyExchangeAlgorithms
                       = fromJust maybeKeyExchangeAlgorithms,
                     sshMessageServerHostKeyAlgorithms
                       = fromJust maybeServerHostKeyAlgorithms,
                     sshMessageEncryptionAlgorithmsClientToServer
                       = fromJust maybeEncryptionAlgorithmsClientToServer,
                     sshMessageEncryptionAlgorithmsServerToClient
                       = fromJust maybeEncryptionAlgorithmsServerToClient,
                     sshMessageMACAlgorithmsClientToServer
                       = fromJust maybeMACAlgorithmsClientToServer,
                     sshMessageMACAlgorithmsServerToClient
                       = fromJust maybeMACAlgorithmsServerToClient,
                     sshMessageCompressionAlgorithmsClientToServer
                       = fromJust maybeCompressionAlgorithmsClientToServer,
                     sshMessageCompressionAlgorithmsServerToClient
                       = fromJust maybeCompressionAlgorithmsServerToClient,
                     sshMessageLanguagesClientToServer
                       = fromJust maybeLanguagesClientToServer,
                     sshMessageLanguagesServerToClient
                       = fromJust maybeLanguagesServerToClient,
                     sshMessageFirstKeyExchangePacketFollows
                       = fromJust maybeFirstKeyExchangePacketFollows
                   }
    Just 21 -> return Nothing -- New keys
    Just 50 -> return Nothing -- User authentication request
    Just 51 -> return Nothing -- User authentication failure
    Just 52 -> return Nothing -- User authentication success
    Just 53 -> return Nothing -- User authentication banner
    Just 80 -> return Nothing -- Global request
    Just 81 -> return Nothing -- Request success
    Just 82 -> return Nothing -- Request failure
    Just 90 -> return Nothing -- Channel open
    Just 91 -> return Nothing -- Channel open confirmation
    Just 92 -> return Nothing -- Channel open failure
    Just 93 -> return Nothing -- Channel window adjust
    Just 94 -> return Nothing -- Channel data
    Just 95 -> return Nothing -- Channel extended data
    Just 96 -> return Nothing -- Channel EOF
    Just 97 -> return Nothing -- Channel close
    Just 98 -> return Nothing -- Channel request
    Just 99 -> return Nothing -- Channel success
    Just 100 -> return Nothing -- Channel failure
    _ -> error "Unknown SSH message code."


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
