module Internal.AbstractStreams (AbstractStream(..),
                                 connectToHostname,
                                 streamReadCRLF)
  where

import Control.Concurrent.MVar
import Data.Char
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Data.Word
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString


data AbstractStream = AbstractStream {
    streamSend :: ByteString -> IO (),
    streamRead :: Int -> IO (Maybe ByteString),
    streamClose :: IO ()
  }


data SocketStream = SocketStream {
    socketStreamSocket :: Socket,
    socketStreamReadBuffer :: MVar ByteString
  }


connectToHostname :: String -> IO AbstractStream
connectToHostname hostname = do
  addressInfoList <- getAddrInfo (Just defaultHints) (Just hostname) Nothing
  case addressInfoList of
    [] -> error "Host not found."
    (AddrInfo { addrAddress = address } : _) -> do
      address <- do
        case address of
          SockAddrInet _ hostAddress ->
            return $ SockAddrInet 22 hostAddress
          SockAddrInet6 _ flowInfo hostAddress scopeID ->
            return $ SockAddrInet6 22 flowInfo hostAddress scopeID
          _ -> error "Address family not supported."
      socket <- do
        case address of
          SockAddrInet _ _ -> socket AF_INET Stream defaultProtocol
          SockAddrInet6 _ _ _ _ -> socket AF_INET6 Stream defaultProtocol
      connect socket address
      readBufferMVar <- newMVar BS.empty
      let socketStream = SocketStream {
                               socketStreamSocket = socket,
                               socketStreamReadBuffer = readBufferMVar
                             }
          stream = AbstractStream {
                         streamSend = socketStreamSend socketStream,
                         streamRead = socketStreamRead socketStream,
                         streamClose = socketStreamClose socketStream
                       }
      return stream


socketStreamSend :: SocketStream -> ByteString -> IO ()
socketStreamSend socketStream bytestring = do
  sendAll (socketStreamSocket socketStream) bytestring


socketStreamRead :: SocketStream -> Int -> IO (Maybe ByteString)
socketStreamRead socketStream desiredLength = do
  if desiredLength == 0
    then return $ Just BS.empty
    else do
      readBuffer <- takeMVar $ socketStreamReadBuffer socketStream
      (readBuffer, atEOF) <- moreBufferIfNull readBuffer
      loop readBuffer atEOF
      where loop :: ByteString -> Bool -> IO (Maybe ByteString)
            loop readBuffer atEOF = do
              if BS.length readBuffer < desiredLength
                then do
                  if atEOF
                    then do
                      putMVar (socketStreamReadBuffer socketStream) BS.empty
                      return Nothing
                    else do
                      (readBuffer, atEOF) <- moreBuffer readBuffer
                      loop readBuffer atEOF
                else do
                  (result, readBuffer)
                    <- return $ BS.splitAt desiredLength readBuffer
                  putMVar (socketStreamReadBuffer socketStream) readBuffer
                  return $ Just result
            moreBufferIfNull :: ByteString -> IO (ByteString, Bool)
            moreBufferIfNull readBuffer = do
              if BS.null readBuffer
                then moreBuffer readBuffer
                else return (readBuffer, False)
            moreBuffer :: ByteString -> IO (ByteString, Bool)
            moreBuffer readBuffer = do
              newData <- recv (socketStreamSocket socketStream) 4096
              if BS.null newData
                then return (readBuffer, True)
                else return (BS.concat [readBuffer, newData], False)
  

socketStreamClose :: SocketStream -> IO ()
socketStreamClose socketStream = do
  sClose $ socketStreamSocket socketStream


streamReadCRLF :: AbstractStream -> IO (Maybe ByteString)
streamReadCRLF stream = do
  loop BS.empty
  where loop result = do
          maybeByte <- streamRead stream 1
          case maybeByte of
            Nothing -> return Nothing
            Just byte | byte == UTF8.fromString "\n" -> 
                         if BS.null result
                           then return $ Just result
                           else return $ Just
                                  $ BS.take (BS.length result - 1) result
                      | otherwise -> loop $ BS.append result byte
