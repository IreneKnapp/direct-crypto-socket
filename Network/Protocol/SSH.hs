module Network.Protocol.SSH (
                             SSHMode(..),
                             SSHTransportState(..),
                             SSHChannelState(..),
                             SSHUserAuthenticationMode(..),
                             SSHMessage(..),
                             startSSH,
                             streamSendSSHMessage,
                             streamReadSSHMessage
                            )
  where

import Control.Concurrent.MVar
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.List as L
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe
import Data.Word
import System.Random

import Internal.AbstractStreams
import Network.Protocol.SSH.Internal
import Network.Protocol.SSH.Types
import qualified Network.Protocol.SSH.Authentication as Authentication
import qualified Network.Protocol.SSH.Channels as Channels
import qualified Network.Protocol.SSH.Global as Global
import qualified Network.Protocol.SSH.MAC as MAC


data SSHStream = SSHStream {
    sshStreamUnderlyingStream :: AbstractStream,
    sshStreamOpen :: MVar Bool,
    sshStreamReadBuffer :: MVar ByteString,
    sshStreamSendMACAlgorithm :: MVar MAC.Algorithm,
    sshStreamSendSequenceNumber :: MVar Word32,
    sshStreamReadMACAlgorithm :: MVar MAC.Algorithm,
    sshStreamReadSequenceNumber :: MVar Word32
  }


startSSH :: AbstractStream -> SSHMode -> IO (AbstractStream, SSHTransportState)
startSSH underlyingStream mode = do
  openMVar <- newMVar True
  readBufferMVar <- newMVar BS.empty
  sendSequenceNumberMVar <- newMVar 0
  sendMACAlgorithmMVar <- newMVar MAC.Algorithm_None
  recvSequenceNumberMVar <- newMVar 0
  recvMACAlgorithmMVar <- newMVar MAC.Algorithm_None
  let sshStream = SSHStream {
                    sshStreamUnderlyingStream = underlyingStream,
                    sshStreamOpen = openMVar,
                    sshStreamReadBuffer = readBufferMVar,
                    sshStreamSendSequenceNumber = sendSequenceNumberMVar,
                    sshStreamSendMACAlgorithm = sendMACAlgorithmMVar,
                    sshStreamReadSequenceNumber = recvSequenceNumberMVar,
                    sshStreamReadMACAlgorithm = recvMACAlgorithmMVar
                  }
      stream = AbstractStream {
                 streamSend = sshStreamSend sshStream,
                 streamRead = sshStreamRead sshStream,
                 streamClose = sshStreamClose sshStream
               }
      transportState = SSHTransportState {
                          sshTransportStateMode
                            = mode,
                          sshTransportStateUserAuthenticationMode
                            = Nothing,
                          sshTransportStateGlobalRequestsPendingSelfAsSender
                            = [],
                          sshTransportStateGlobalRequestsPendingSelfAsRecipient
                            = [],
                          sshTransportStateChannelOpensPendingSelfAsSender
                            = [],
                          sshTransportStateChannelOpensPendingSelfAsRecipient
                            = [],
                          sshTransportStateChannelsByLocalID
                            = Map.empty,
                          sshTransportStateChannelsByRemoteID
                            = Map.empty
                       }
  return (stream, transportState)


sshStreamSend :: SSHStream -> ByteString -> IO ()
sshStreamSend sshStream payload = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  macAlgorithm <- readMVar $ sshStreamSendMACAlgorithm sshStream
  sequenceNumber <- takeMVar $ sshStreamSendSequenceNumber sshStream
  putMVar (sshStreamSendSequenceNumber sshStream) $ sequenceNumber + 1
  let correctMAC =
        MAC.algorithmComputeCode macAlgorithm
                                 sequenceNumber
                                 payload
      blockSize = 8
      payloadLength = BS.length payload
      minimumPaddingLength = blockSize
                             - (mod (4 + 1 + payloadLength + 4) blockSize)
                             + 4
      maximumAdditionalPaddingBlocks =
        (fromIntegral (maxBound :: Word8) - minimumPaddingLength)
        `div` blockSize
  additionalPaddingBlocks
    <- getStdRandom $ randomR (0, maximumAdditionalPaddingBlocks)
  let totalPaddingLength = minimumPaddingLength
                           + blockSize * additionalPaddingBlocks
      packetLength = payloadLength + totalPaddingLength + 1
  padding
    <- mapM (\_ -> getStdRandom random) [1..totalPaddingLength]
       >>= return . BS.pack
  let packet = BS.concat [packWord32 $ fromIntegral packetLength,
                          packWord8 $ fromIntegral totalPaddingLength,
                          payload,
                          padding,
                          correctMAC]
      stream = sshStreamUnderlyingStream sshStream
  streamSend stream packet


sshStreamRead :: SSHStream -> Int -> IO (Maybe ByteString)
sshStreamRead sshStream desiredLength = do
  if desiredLength == 0
    then return $ Just BS.empty
    else do
      readBuffer <- takeMVar $ sshStreamReadBuffer sshStream
      (readBuffer, atEOF) <- moreBufferIfNull readBuffer
      loop readBuffer atEOF
      where loop :: ByteString -> Bool -> IO (Maybe ByteString)
            loop readBuffer atEOF = do
              if BS.length readBuffer < desiredLength
                then do
                  if atEOF
                    then do
                      putMVar (sshStreamReadBuffer sshStream) BS.empty
                      return Nothing
                    else do
                      (readBuffer, atEOF) <- moreBuffer readBuffer
                      loop readBuffer atEOF
                else do
                  (result, readBuffer)
                    <- return $ BS.splitAt desiredLength readBuffer
                  putMVar (sshStreamReadBuffer sshStream) readBuffer
                  return $ Just result
            moreBufferIfNull :: ByteString -> IO (ByteString, Bool)
            moreBufferIfNull readBuffer = do
              if BS.null readBuffer
                then moreBuffer readBuffer
                else return (readBuffer, False)
            moreBuffer :: ByteString -> IO (ByteString, Bool)
            moreBuffer readBuffer = do
              maybeNewData <- sshStreamReadPacket sshStream
              case maybeNewData of
                Nothing -> return (readBuffer, True)
                Just newData -> return (BS.concat [readBuffer, newData], False)


sshStreamReadPacket :: SSHStream -> IO (Maybe ByteString)
sshStreamReadPacket sshStream = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  let stream = sshStreamUnderlyingStream sshStream
  macAlgorithm <- readMVar $ sshStreamReadMACAlgorithm sshStream
  sequenceNumber <- takeMVar $ sshStreamReadSequenceNumber sshStream
  putMVar (sshStreamReadSequenceNumber sshStream) $ sequenceNumber + 1
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


streamSendSSHMessage :: AbstractStream -> SSHMessage -> IO ()
streamSendSSHMessage stream message = do
  putStrLn $ show message
  case message of
    -- TODO everything else
    SSHMessageDisconnect { } -> do
      streamSend stream
       $ BS.concat [packWord8 1,
                    packWord32 $ sshMessageReasonCode message,
                    packString $ sshMessageDescription message,
                    packString $ sshMessageLanguageTag message]
    SSHMessageKeyExchangeInit { } -> do
      streamSend stream
       $ BS.concat [packWord8 20,
                    sshMessageCookie message,
                    packNameList
                     $ sshMessageKeyExchangeAlgorithms message,
                    packNameList
                     $ sshMessageServerHostKeyAlgorithms message,
                    packNameList
                     $ sshMessageEncryptionAlgorithmsClientToServer message,
                    packNameList
                     $ sshMessageEncryptionAlgorithmsServerToClient message,
                    packNameList
                     $ sshMessageMACAlgorithmsClientToServer message,
                    packNameList
                     $ sshMessageMACAlgorithmsServerToClient message,
                    packNameList
                     $ sshMessageCompressionAlgorithmsClientToServer message,
                    packNameList
                     $ sshMessageCompressionAlgorithmsServerToClient message,
                    packNameList
                     $ sshMessageLanguagesClientToServer message,
                    packNameList
                     $ sshMessageLanguagesServerToClient message,
                    packBoolean
                     $ sshMessageFirstKeyExchangePacketFollows message,
                    packWord32 0]


streamReadSSHMessage :: AbstractStream
                     -> SSHTransportState
                     -> IO (Maybe (SSHMessage,
                                   Maybe SSHMessage,
                                   SSHTransportState))
streamReadSSHMessage stream transportState = do
  maybeMessageType <- streamReadWord8 stream
  case maybeMessageType of
    Nothing -> error "Incoming SSH stream unexpectedly ended."
    Just 1 -> do
      maybeReasonCode <- streamReadWord32 stream
      maybeDescription <- streamReadString stream
      maybeLanguageTag <- streamReadString stream
      case maybeLanguageTag of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageDisconnect {
                      sshMessageReasonCode
                        = fromJust maybeReasonCode,
                      sshMessageDescription
                        = fromJust maybeDescription,
                      sshMessageLanguageTag
                        = fromJust maybeLanguageTag
                    },
                  Nothing,
                  transportState)
    Just 2 -> do
      maybeMessageData <- streamReadBinaryString stream
      case maybeMessageData of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageIgnore {
                      sshMessageData
                        = fromJust maybeMessageData
                    },
                  Nothing,
                  transportState)
    Just 3 -> do
      maybePacketSequenceNumber <- streamReadWord32 stream
      case maybePacketSequenceNumber of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageUnimplemented {
                      sshMessagePacketSequenceNumber
                        = fromJust maybePacketSequenceNumber
                    },
                  Nothing,
                  transportState)
    Just 4 -> do
      maybeAlwaysDisplay <- streamReadBoolean stream
      maybeText <- streamReadString stream
      maybeLanguageTag <- streamReadString stream
      case maybeLanguageTag of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageDebug {
                      sshMessageAlwaysDisplay
                        = fromJust maybeAlwaysDisplay,
                      sshMessageText
                        = fromJust maybeText,
                      sshMessageLanguageTag
                        = fromJust maybeLanguageTag
                    },
                  Nothing,
                  transportState)
    Just 5 -> do
      maybeServiceName <- streamReadString stream
      case maybeServiceName of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageServiceRequest {
                      sshMessageServiceName
                        = fromJust maybeServiceName
                    },
                  Nothing,
                  transportState)
    Just 6 -> do
      maybeServiceName <- streamReadString stream
      case maybeServiceName of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageServiceAccept {
                      sshMessageServiceName
                        = fromJust maybeServiceName
                    },
                  Nothing,
                  transportState)
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
                 (SSHMessageKeyExchangeInit {
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
                    },
                  Nothing,
                  transportState)
    Just 21 -> do
      return $ Just (SSHMessageNewKeys { },
                     Nothing,
                     transportState)
    Just 50 -> do
      maybeUserName <- streamReadString stream
      maybeServiceName <- streamReadString stream
      maybeMethodName <- streamReadString stream
      maybeMethodFields
        <- case maybeMethodName of
             Nothing -> return Nothing
             Just methodName ->
               Authentication.streamReadMethodFields stream methodName
      case maybeMethodFields of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageUserAuthenticationRequest {
                      sshMessageUserName
                        = fromJust maybeUserName,
                      sshMessageServiceName
                        = fromJust maybeServiceName,
                      sshMessageMethodName
                        = fromJust maybeMethodName,
                      sshMessageMethodFields
                        = fromJust maybeMethodFields
                    },
                  Nothing,
                  transportState)
    Just 51 -> do
      maybeAuthenticationMethods <- streamReadNameList stream
      maybePartialSuccess <- streamReadBoolean stream
      case maybePartialSuccess of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageUserAuthenticationFailure {
                      sshMessageAuthenticationMethods
                        = fromJust maybeAuthenticationMethods,
                      sshMessagePartialSuccess
                        = fromJust maybePartialSuccess
                    },
                  Nothing,
                  transportState)
    Just 52 -> do
      return $ Just (SSHMessageUserAuthenticationSuccess { },
                     Nothing,
                     transportState)
    Just 53 -> do
      maybeText <- streamReadString stream
      maybeLanguageTag <- streamReadString stream
      case maybeLanguageTag of
        Nothing -> return Nothing
        Just _ ->
          return $ Just
                 (SSHMessageUserAuthenticationBanner {
                      sshMessageText
                        = fromJust maybeText,
                      sshMessageLanguageTag
                        = fromJust maybeLanguageTag
                    },
                  Nothing,
                  transportState)
    Just 60 -> do
      case sshTransportStateUserAuthenticationMode transportState of
        Nothing -> error $ "User-authentication SSH message received when "
                           ++ "transport not in appropriate state."
        Just SSHUserAuthenticationModePublicKey -> do
          maybeAlgorithmName <- streamReadString stream
          maybeBlob <- streamReadBinaryString stream
          case maybeBlob of
            Nothing -> return Nothing
            Just _ -> do
              return $ Just
                     (SSHMessageUserAuthenticationPublicKeyOkay {
                          sshMessageAlgorithmName
                            = fromJust maybeAlgorithmName,
                          sshMessageBlob
                            = fromJust maybeBlob
                        },
                      Nothing,
                      transportState)
        Just SSHUserAuthenticationModePassword -> do
          maybeText <- streamReadString stream
          maybeLanguageTag <- streamReadString stream
          case maybeLanguageTag of
            Nothing -> return Nothing
            Just _ -> do
              return $ Just
                     (SSHMessageUserAuthenticationPasswordChangeRequest {
                          sshMessageText
                            = fromJust maybeText,
                          sshMessageLanguageTag
                            = fromJust maybeLanguageTag
                        },
                      Nothing,
                      transportState)
    Just 80 -> do
      maybeRequestName <- streamReadString stream
      maybeWantReply <- streamReadBoolean stream
      maybeRequestFields
        <- case maybeRequestName of
             Nothing -> return Nothing
             Just requestName ->
               Global.streamReadRequestFields stream requestName
      case maybeRequestFields of
        Nothing -> return Nothing
        Just _ -> do
          let result = SSHMessageGlobalRequest {
                           sshMessageRequestName
                             = fromJust maybeRequestName,
                           sshMessageWantReply
                             = fromJust maybeWantReply,
                           sshMessageRequestFields
                             = fromJust maybeRequestFields
                         }
              oldRequestsPending
                = sshTransportStateGlobalRequestsPendingSelfAsRecipient
                   transportState
              newRequestsPending
                = if fromJust maybeWantReply
                    then oldRequestsPending ++ [result]
                    else oldRequestsPending
          transportState
            <- return transportState {
                          sshTransportStateGlobalRequestsPendingSelfAsRecipient
                            = newRequestsPending
                        }
          return $ Just (result,
                         Nothing,
                         transportState)
    Just 81 -> do
      let oldRequestsPending
            = sshTransportStateGlobalRequestsPendingSelfAsSender
               transportState
          (maybeMatchingRequest, newRequestsPending)
            = case oldRequestsPending of
                [] -> (Nothing, [])
                (matchingRequest:rest) -> (Just matchingRequest, rest)
          maybeRequestName
            = fmap sshMessageRequestName maybeMatchingRequest
      transportState
        <- return transportState {
                      sshTransportStateGlobalRequestsPendingSelfAsSender
                        = newRequestsPending
                    }
      maybeResponseFields
        <- case maybeRequestName of
             Nothing -> error $ "SSH global response received "
                              ++ "without matching request."
             Just requestName ->
               Global.streamReadResponseFields
                stream
                requestName
                (sshMessageRequestFields $ fromJust maybeMatchingRequest)
      case maybeResponseFields of
        Nothing -> return Nothing
        Just _ -> do
          let result = SSHMessageRequestSuccess {
                           sshMessageResponseFields
                             = fromJust maybeResponseFields
                         }
          return $ Just (result,
                         maybeMatchingRequest,
                         transportState)
    Just 82 -> do
      return $ Just (SSHMessageRequestFailure { },
                     Nothing,
                     transportState)
    Just 90 -> do
      maybeChannelType <- streamReadString stream
      maybeSenderChannel <- streamReadWord32 stream
      maybeInitialWindowSize <- streamReadWord32 stream
      maybeMaximumPacketSize <- streamReadWord32 stream
      maybeChannelOpenFields
        <- case maybeChannelType of
             Nothing -> return Nothing
             Just channelType ->
               Channels.streamReadChannelOpenFields stream channelType
      case maybeChannelOpenFields of
        Nothing -> return Nothing
        Just _ -> do
          let result = SSHMessageChannelOpen {
                           sshMessageChannelType
                             = fromJust maybeChannelType,
                           sshMessageSenderChannel
                             = fromJust maybeSenderChannel,
                           sshMessageInitialWindowSize
                             = fromJust maybeInitialWindowSize,
                           sshMessageMaximumPacketSize
                             = fromJust maybeMaximumPacketSize,
                           sshMessageChannelOpenFields
                             = fromJust maybeChannelOpenFields
                         }
              oldChannelOpensPending
                = sshTransportStateChannelOpensPendingSelfAsRecipient
                   transportState
              newChannelOpensPending
                = oldChannelOpensPending ++ [result]
          transportState
            <- return transportState {
                          sshTransportStateChannelOpensPendingSelfAsRecipient
                            = newChannelOpensPending
                        }
          return $ Just (result,
                         Nothing,
                         transportState)
    Just 91 -> do
      let oldChannelOpensPending
            = sshTransportStateChannelOpensPendingSelfAsSender
               transportState
          (maybeMatchingChannelOpen, newChannelOpensPending)
            = case oldChannelOpensPending of
                [] -> (Nothing, [])
                (matchingChannelOpen:rest) -> (Just matchingChannelOpen, rest)
          maybeChannelType
            = fmap sshMessageChannelType maybeMatchingChannelOpen
      transportState
        <- return transportState {
                      sshTransportStateChannelOpensPendingSelfAsSender
                        = newChannelOpensPending
                    }
      maybeRecipientChannel <- streamReadWord32 stream
      maybeSenderChannel <- streamReadWord32 stream
      maybeInitialWindowSize <- streamReadWord32 stream
      maybeMaximumPacketSize <- streamReadWord32 stream
      maybeChannelOpenConfirmationFields
        <- case maybeChannelType of
             Nothing -> error $ "SSH channel-open response received "
                                ++ "without matching request."
             Just channelType ->
               Channels.streamReadChannelOpenConfirmationFields
                stream
                channelType
                (sshMessageChannelOpenFields
                  $ fromJust maybeMatchingChannelOpen)
      case maybeChannelOpenConfirmationFields of
        Nothing -> return Nothing
        Just _ -> do
          let result = SSHMessageChannelOpenConfirmation {
                           sshMessageRecipientChannel
                             = fromJust maybeRecipientChannel,
                           sshMessageSenderChannel
                             = fromJust maybeSenderChannel,
                           sshMessageInitialWindowSize
                             = fromJust maybeInitialWindowSize,
                           sshMessageMaximumPacketSize
                             = fromJust maybeMaximumPacketSize,
                           sshMessageChannelOpenConfirmationFields
                             = fromJust maybeChannelOpenConfirmationFields
                         }
          return $ Just (result,
                         maybeMatchingChannelOpen,
                         transportState)
    Just 92 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      maybeReasonCode <- streamReadWord32 stream
      maybeDescription <- streamReadString stream
      maybeLanguageTag <- streamReadString stream
      case maybeLanguageTag of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelOpenFailure {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel,
                              sshMessageReasonCode
                                = fromJust maybeReasonCode,
                              sshMessageDescription
                                = fromJust maybeDescription,
                              sshMessageLanguageTag
                                = fromJust maybeLanguageTag
                            },
                          Nothing,
                          transportState)
    Just 93 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      maybeBytesToAdd <- streamReadWord32 stream
      case maybeBytesToAdd of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelWindowAdjust {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel,
                              sshMessageBytesToAdd
                                = fromJust maybeBytesToAdd
                            },
                          Nothing,
                          transportState)
    Just 94 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      maybeData <- streamReadBinaryString stream
      case maybeData of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelData {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel,
                              sshMessageData
                                = fromJust maybeData
                            },
                          Nothing,
                          transportState)
    Just 95 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      maybeDataTypeCode <- streamReadWord32 stream
      maybeData <- streamReadBinaryString stream
      case maybeData of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelExtendedData {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel,
                              sshMessageDataTypeCode
                                = fromJust maybeDataTypeCode,
                              sshMessageData
                                = fromJust maybeData
                            },
                          Nothing,
                          transportState)
    Just 96 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      case maybeRecipientChannel of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelEOF {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel
                            },
                          Nothing,
                          transportState)
    Just 97 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      case maybeRecipientChannel of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelClose {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel
                            },
                          Nothing,
                          transportState)
    Just 98 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      maybeRequestType <- streamReadString stream
      maybeWantReply <- streamReadBoolean stream
      maybeChannelRequestFields
        <- case maybeRequestType of
             Nothing -> return Nothing
             Just requestType ->
               Channels.streamReadChannelRequestFields stream requestType
      case maybeChannelRequestFields of
        Nothing -> return Nothing
        Just _ -> do
          let result = SSHMessageChannelRequest {
                           sshMessageRecipientChannel
                             = fromJust maybeRecipientChannel,
                           sshMessageRequestType
                             = fromJust maybeRequestType,
                           sshMessageWantReply
                             = fromJust maybeWantReply,
                           sshMessageChannelRequestFields
                             = fromJust maybeChannelRequestFields
                         }
              oldChannelsByLocalID
                = sshTransportStateChannelsByLocalID transportState
              oldChannelsByRemoteID
                = sshTransportStateChannelsByRemoteID transportState
              maybeOldChannel
                = Map.lookup (fromJust maybeRecipientChannel)
                             oldChannelsByRemoteID
          oldChannel <-
            case maybeOldChannel of
              Nothing -> error $ "Attempting to send SSH channel request "
                                 ++ "for channel that doesn't exist."
              Just oldChannel -> return oldChannel
          let oldRequestsPending
                = sshChannelStateRequestsPendingSelfAsSender oldChannel
              newRequestsPending
                = if fromJust maybeWantReply
                    then oldRequestsPending ++ [result]
                    else oldRequestsPending
              newChannel
                = oldChannel {
                      sshChannelStateRequestsPendingSelfAsSender
                        = newRequestsPending
                    }
              newChannelsByLocalID
                = Map.insert (sshChannelStateLocalID newChannel)
                             newChannel
                             oldChannelsByLocalID
              newChannelsByRemoteID
                = Map.insert (sshChannelStateRemoteID newChannel)
                             newChannel
                             oldChannelsByRemoteID
          transportState
            <- return $ transportState {
                            sshTransportStateChannelsByLocalID
                              = newChannelsByLocalID,
                            sshTransportStateChannelsByRemoteID
                              = newChannelsByRemoteID
                          }
          return $ Just (result,
                         Nothing,
                         transportState)
    Just 99 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      case maybeRecipientChannel of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelSuccess {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel
                            },
                          Nothing,
                          transportState)
    Just 100 -> do
      maybeRecipientChannel <- streamReadWord32 stream
      case maybeRecipientChannel of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         (SSHMessageChannelFailure {
                              sshMessageRecipientChannel
                                = fromJust maybeRecipientChannel
                            },
                          Nothing,
                          transportState)
    _ -> error "Unknown SSH message code."
