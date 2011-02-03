module Network.Protocol.SSH (
                             SSHMode(..),
                             SSHTransportState(..),
                             SSHChannelState(..),
                             SSHUserAuthenticationMode(..),
                             SSHMessage(..),
                             startSSH,
                             streamSendSSHMessage,
                             streamReadSSHMessage,
                             packSSHMessage,
                             unpackSSHMessage
                            )
  where

import Control.Concurrent.MVar
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Data.Dynamic
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


data ThingType = RawType Int
               | Word32Type
               | Word8Type
               | NameListType
               | StringType
               | BinaryStringType
               | BooleanType


startSSH :: AbstractStream -> SSHMode -> IO SSHTransportState
startSSH underlyingStream mode = do
  let transportState = SSHTransportState {
                          sshTransportStateMode
                            = mode,
                          sshTransportStateExpecting
                            = SSHAnything,
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
  return transportState


streamSendPacket :: AbstractStream
                    -> SSHTransportState
                    -> ByteString
                    -> IO SSHTransportState
streamSendPacket stream transportState payload = do
  let correctMAC =
        BS.empty
        {-
        MAC.algorithmComputeCode macAlgorithm
                                 sequenceNumber
                                 payload
         -}
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
  streamSend stream packet
  return transportState


streamReadPacket :: AbstractStream
                    -> SSHTransportState
                    -> IO (Maybe ByteString, SSHTransportState)
streamReadPacket stream transportState = do
  maybePacketLength <- streamReadWord32 stream
  case maybePacketLength of
    Nothing -> return (Nothing, transportState)
    Just packetLength -> do
      maybePaddingLength <- streamReadWord8 stream
      case maybePaddingLength of
        Nothing -> return (Nothing, transportState)
        Just paddingLength -> do
          maybePayload
            <- streamRead stream
                $ fromIntegral $ packetLength - (fromIntegral paddingLength) - 1
          case maybePayload of
            Nothing -> return (Nothing, transportState)
            Just payload -> do
              maybePadding
                <- streamRead stream $ fromIntegral paddingLength
              case maybePadding of
                Nothing -> return (Nothing, transportState)
                Just _ -> do
                  let macLength = 0 -- MAC.algorithmCodeLength macAlgorithm
                  maybeMAC <- streamRead stream macLength
                  case maybeMAC of
                    Nothing -> return (Nothing, transportState)
                    Just mac -> do
                      let correctMAC =
                            BS.empty
                            {-
                            MAC.algorithmComputeCode macAlgorithm
                                                     sequenceNumber
                                                     payload
                             -}
                          maybePayload =
                            if mac == correctMAC
                              then Just payload
                              else Nothing
                      return (maybePayload, transportState)


streamSendSSHMessage :: AbstractStream
                     -> SSHTransportState
                     -> SSHMessage
                     -> IO SSHTransportState
streamSendSSHMessage stream transportState message = do
  let (packet, transportState') = packSSHMessage transportState message
  streamSendPacket stream transportState packet
  return transportState'


streamReadSSHMessage :: AbstractStream
                     -> SSHTransportState
                     -> IO (Maybe (SSHMessage,
                                   Maybe SSHMessage,
                                   SSHTransportState))
streamReadSSHMessage stream transportState = do
  (maybePacket, transportState) <- streamReadPacket stream transportState
  case maybePacket of
    Nothing -> return Nothing
    Just packet -> do
      let (result, trailer) = unpackSSHMessage transportState packet
      if not $ BS.null trailer
        then error $ "Trailing data after SSH packet."
        else return result


packSSHMessage :: SSHTransportState
               -> SSHMessage
               -> (ByteString, SSHTransportState)
packSSHMessage transportState message =
  case message of
    -- TODO everything else
    SSHMessageDisconnect { } ->
      (BS.concat [packWord8 1,
                  packWord32 $ sshMessageReasonCode message,
                  packString $ sshMessageDescription message,
                  packString $ sshMessageLanguageTag message],
       transportState)
    SSHMessageKeyExchangeInit { } -> do
      (BS.concat [packWord8 20,
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
                  packWord32 0],
       transportState)


unpackThings :: Dynamic
             -> [ThingType]
             -> ByteString
             -> (Maybe Dynamic, ByteString)
unpackThings constructor thingTypes bytestring =
  let visit maybeResults (thingType:remainingThingTypes) bytestring =
        case thingType of
          RawType size ->
            let maybeThing =
                  if BS.length bytestring >= size
                    then Just $ BS.take size bytestring
                    else Nothing
                remainingBytestring = BS.drop size bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
          Word32Type ->
            let (maybeThing, remainingBytestring) = unpackWord32 bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
          Word8Type ->
            let (maybeThing, remainingBytestring) = unpackWord8 bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
          NameListType ->
            let (maybeThing, remainingBytestring) = unpackNameList bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
          StringType ->
            let (maybeThing, remainingBytestring) = unpackString bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
          BinaryStringType ->
            let (maybeThing, remainingBytestring) =
                  unpackBinaryString bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
          BooleanType ->
            let (maybeThing, remainingBytestring) = unpackBoolean bytestring
            in visit (maybeResults ++ [fmap toDyn maybeThing])
                     remainingThingTypes
                     remainingBytestring
      visit maybeResults [] bytestring =
        (maybeResults, bytestring)
      (maybeResults, remainingBytestring) = visit [] thingTypes bytestring
      results = if all isJust maybeResults
                  then Just $ map fromJust maybeResults
                  else Nothing
      maybeConstructed = fmap (\results ->
                                 foldl (\constructor result ->
                                          dynApp constructor result)
                                       constructor
                                       results)
                              results
  in (maybeConstructed, remainingBytestring)


unpackSSHMessage :: SSHTransportState
                 -> ByteString
                 -> (Maybe (SSHMessage,
                            Maybe SSHMessage,
                            SSHTransportState),
                     ByteString)
unpackSSHMessage transportState bytestring0 =
  let (maybeMessageType, bytestring1) = unpackWord8 bytestring0
      fromThing = fromJust . fromDynamic
  in case maybeMessageType of
       Nothing -> (Nothing, bytestring1)
{-
       Just 1 ->
         
         let (maybeReasonCode, bytestring2) = unpackWord32 bytestring1
             (maybeDescription, bytestring3) = unpackString bytestring2
             (maybeLanguageTag, bytestring4) = unpackString bytestring3
 in case maybeLanguageTag of
              Nothing -> (Nothing, bytestring4)
              Just _ ->
                (Just (SSHMessageDisconnect {
                           sshMessageReasonCode
                             = fromJust maybeReasonCode,
                           sshMessageDescription
                             = fromJust maybeDescription,
                           sshMessageLanguageTag
                             = fromJust maybeLanguageTag
                         },
                       Nothing,
                       transportState),
                 bytestring4)
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
-}
       Just 20 ->
         let (maybeRecord, bytestring2)
               = unpackThings (toDyn SSHMessageKeyExchangeInit)
                              [RawType 16,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               NameListType,
                               BooleanType]
                              bytestring1
             (maybePadding, bytestring3) = unpackWord32 bytestring2
         in case (maybeRecord, maybePadding) of
              (Just record, Just _) ->
                (Just (fromThing record,
                       Nothing,
                       transportState),
                 bytestring3)
              _ -> (Nothing, bytestring3)
{-
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
-}
       _ -> error "Unknown SSH message code."
