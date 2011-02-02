module Main (main) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Data.Maybe
import System.Environment
import System.Random

import Internal.AbstractStreams
import Network.Protocol.SSH
import qualified Network.Protocol.SSH.KeyExchange as KeyExchange
import qualified Network.Protocol.SSH.MAC as MAC
import qualified Network.Protocol.SSH.ServerHostKey as ServerHostKey
import qualified Network.Protocol.SSH.Encryption as Encryption
import qualified Network.Protocol.SSH.Compression as Compression


main :: IO ()
main = do
  arguments <- getArgs
  case arguments of
    [hostname] -> sshClient hostname
    _ -> usage


usage :: IO ()
usage = do
  programName <- getProgName
  putStrLn $ "Usage: " ++ programName ++ " hostname"


sshClient :: String -> IO ()
sshClient hostname = do
  putStrLn $ "Connecting..."
  stream <- connectToHostname hostname
  putStrLn $ "Initiating session..."
  streamSend stream $ UTF8.fromString "SSH-2.0-directssh1.0\r\n"
  let loopForIdentification :: IO (Maybe ByteString)
      loopForIdentification = do
        maybeIdentificationOrMOTD <- streamReadCRLF stream
        case maybeIdentificationOrMOTD of
          Nothing -> return Nothing
          Just identificationOrMOTD ->
            if BS.isPrefixOf (UTF8.fromString "SSH-") identificationOrMOTD
              then return $ Just identificationOrMOTD
              else loopForIdentification
  maybeIdentification <- loopForIdentification
  case maybeIdentification of
    Nothing -> error "SSH identification string not received."
    Just identification -> do
      (stream, transportState) <- startSSH stream SSHClient
      cookie <- generateCookie
      let outboundKeyExchangeInitMessage
            = SSHMessageKeyExchangeInit {
                  sshMessageCookie = cookie,
                  sshMessageKeyExchangeAlgorithms =
                    KeyExchange.knownAlgorithmNames,
                  sshMessageServerHostKeyAlgorithms =
                    ServerHostKey.knownAlgorithmNames,
                  sshMessageEncryptionAlgorithmsClientToServer =
                    Encryption.knownAlgorithmNames,
                  sshMessageEncryptionAlgorithmsServerToClient =
                    Encryption.knownAlgorithmNames,
                  sshMessageMACAlgorithmsClientToServer =
                    MAC.knownAlgorithmNames,
                  sshMessageMACAlgorithmsServerToClient =
                    MAC.knownAlgorithmNames,
                  sshMessageCompressionAlgorithmsClientToServer =
                    Compression.knownAlgorithmNames,
                  sshMessageCompressionAlgorithmsServerToClient =
                    Compression.knownAlgorithmNames,
                  sshMessageLanguagesClientToServer = [""],
                  sshMessageLanguagesServerToClient = [""],
                  sshMessageFirstKeyExchangePacketFollows = False
                }
      streamSendSSHMessage stream outboundKeyExchangeInitMessage
      maybeResult <- streamReadSSHMessage stream transportState
      case maybeResult of
        Nothing -> error "Unexpectedly disconnected."
        Just (inboundKeyExchangeInitMessage, _, transportState) -> do
          let (clientKeyExchangeInitMessage,
               serverKeyExchangeInitMessage)
                = case sshTransportStateMode transportState of
                    SSHClient -> (outboundKeyExchangeInitMessage,
                                  inboundKeyExchangeInitMessage)
                    SSHServer -> (inboundKeyExchangeInitMessage,
                                  outboundKeyExchangeInitMessage)
              clientKeyExchangeAlgorithms
                = catMaybes
                   $ map KeyExchange.algorithmFromName
                         $ sshMessageKeyExchangeAlgorithms
                            clientKeyExchangeInitMessage
              serverKeyExchangeAlgorithms
                = catMaybes
                   $ map KeyExchange.algorithmFromName
                         $ sshMessageKeyExchangeAlgorithms
                            serverKeyExchangeInitMessage
              clientHostKeyAlgorithms
                = catMaybes
                   $ map ServerHostKey.algorithmFromName
                         $ sshMessageServerHostKeyAlgorithms
                            clientKeyExchangeInitMessage
              serverHostKeyAlgorithms
                = catMaybes
                   $ map ServerHostKey.algorithmFromName
                         $ sshMessageServerHostKeyAlgorithms
                            serverKeyExchangeInitMessage
              maybeKeyExchangeAlgorithm
                = KeyExchange.computeAlgorithm clientKeyExchangeAlgorithms
                                               serverKeyExchangeAlgorithms
                                               clientHostKeyAlgorithms
                                               serverHostKeyAlgorithms
          case maybeKeyExchangeAlgorithm of
            Nothing -> do
              streamClose stream
              error "No appropriate SSH key-exchange algorithm."
            Just keyExchangeAlgorithm -> do
              let maybeServerHostKeyAlgorithm
                    = ServerHostKey.computeAlgorithm keyExchangeAlgorithm
                                                     clientHostKeyAlgorithms
                                                     serverHostKeyAlgorithms
              case maybeServerHostKeyAlgorithm of
                Nothing -> do
                  streamClose stream
                  error "No appropriate SSH server-host-key algorithm."
                Just serverHostKeyAlgorithm -> do
                  let clientEncryptionAlgorithmsClientToServer
                        = catMaybes
                           $ map Encryption.algorithmFromName
                                 $ sshMessageEncryptionAlgorithmsClientToServer
                                    clientKeyExchangeInitMessage
                      serverEncryptionAlgorithmsClientToServer
                        = catMaybes
                           $ map Encryption.algorithmFromName
                                 $ sshMessageEncryptionAlgorithmsClientToServer
                                    serverKeyExchangeInitMessage
                      clientEncryptionAlgorithmsServerToClient
                        = catMaybes
                           $ map Encryption.algorithmFromName
                                 $ sshMessageEncryptionAlgorithmsServerToClient
                                    clientKeyExchangeInitMessage
                      serverEncryptionAlgorithmsServerToClient
                        = catMaybes
                           $ map Encryption.algorithmFromName
                                 $ sshMessageEncryptionAlgorithmsServerToClient
                                    serverKeyExchangeInitMessage
                      maybeEncryptionAlgorithmClientToServer
                        = Encryption.computeAlgorithm
                           clientEncryptionAlgorithmsClientToServer
                           serverEncryptionAlgorithmsClientToServer
                      maybeEncryptionAlgorithmServerToClient
                        = Encryption.computeAlgorithm
                           clientEncryptionAlgorithmsServerToClient
                           serverEncryptionAlgorithmsServerToClient
                  case (maybeEncryptionAlgorithmClientToServer,
                        maybeEncryptionAlgorithmServerToClient) of
                    (Just encryptionAlgorithmClientToServer,
                     Just encryptionAlgorithmServerToClient) -> do
                      let clientMACAlgorithmsClientToServer
                            = catMaybes
                               $ map MAC.algorithmFromName
                                     $ sshMessageMACAlgorithmsClientToServer
                                        clientKeyExchangeInitMessage
                          serverMACAlgorithmsClientToServer
                            = catMaybes
                               $ map MAC.algorithmFromName
                                     $ sshMessageMACAlgorithmsClientToServer
                                        serverKeyExchangeInitMessage
                          clientMACAlgorithmsServerToClient
                            = catMaybes
                               $ map MAC.algorithmFromName
                                     $ sshMessageMACAlgorithmsServerToClient
                                        clientKeyExchangeInitMessage
                          serverMACAlgorithmsServerToClient
                            = catMaybes
                               $ map MAC.algorithmFromName
                                     $ sshMessageMACAlgorithmsServerToClient
                                        serverKeyExchangeInitMessage
                          maybeMACAlgorithmClientToServer
                            = MAC.computeAlgorithm
                               clientMACAlgorithmsClientToServer
                               serverMACAlgorithmsClientToServer
                          maybeMACAlgorithmServerToClient
                            = MAC.computeAlgorithm
                               clientMACAlgorithmsServerToClient
                               serverMACAlgorithmsServerToClient
                      case (maybeMACAlgorithmClientToServer,
                            maybeMACAlgorithmServerToClient) of
                        (Just macAlgorithmClientToServer,
                         Just macAlgorithmServerToClient) -> do
                          putStrLn $ "Connected."
                          let loop transportState = do
                                maybeResult <- streamReadSSHMessage stream transportState
                                case maybeResult of
                                  Nothing -> return ()
                                  Just (message, _, transportState) -> do
                                    putStrLn $ show message
                                    putStrLn $ ""
                                    loop transportState
                          loop transportState
                          putStrLn $ "Disconnecting."
                          streamClose stream
                        _ -> do
                         streamClose stream
                         error
                          "No appropriate SSH message-authentication algorithm."
                    _ -> do
                      streamClose stream
                      error "No appropriate SSH encryption algorithm."
                  putStrLn $ "Connected."


generateCookie :: IO ByteString
generateCookie = do
  mapM (\_ -> getStdRandom random) [1..16] >>= return . BS.pack
