{-# LANGUAGE StandaloneDeriving, FlexibleContexts, DeriveDataTypeable #-}
module Main (main) where

import Control.Monad.IO.Class
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char
import Data.Dynamic
import Data.List
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Word
import Numeric
import System.Console.Haskeline
import System.Environment

import qualified Data.Digest.MD5 as MD5

import Network.Protocol.SSH


instance (Typeable (m a)) => Typeable (InputT m a) where
  typeOf x = mkTyConApp (mkTyCon "System.Console.Haskeline.InputT") []


data CommandCategory = StandardCommand
                     | MessageDigestCommand
                     | CipherCommand
                       deriving (Eq)


data Command = Command CommandCategory
                       String
                       [Parameter]
                       [Parameter]
                       Dynamic


data Parameter = StringParameter
               | InputFileParameter


main :: IO ()
main = do
  runInputT defaultSettings main'
  where main' :: InputT IO ()
        main' = do
          arguments <- liftIO $ getArgs
          case arguments of
            [] -> commandLoop
            (command:parameters) ->
              processCommand (map toLower command) parameters
        commandLoop :: InputT IO ()
        commandLoop = do
          input <- getInputLine "Crypto> "
          case fmap smartWords input of
            Nothing -> return ()
            Just [] -> commandLoop
            Just (command:parameters)
              | map toLower command == "quit" -> return ()
              | otherwise -> do
                  processCommand (map toLower command) parameters
                  commandLoop


processCommand :: String -> [String] -> InputT IO ()
processCommand commandName parameters = do
  case parameters of
    [] -> commandHelp Nothing
    [item] -> commandHelp (Just item)
    _ -> return ()


commandTable :: Map String Command
commandTable =
  Map.fromList [("help", Command StandardCommand
                                 "help"
                                 []
                                 [StringParameter]
                                 $ toDyn commandHelp),
                ("md5", Command MessageDigestCommand
                                "md5"
                                [InputFileParameter]
                                []
                                $ toDyn commandMD5)]


commandHelp :: Maybe String -> InputT IO ()
commandHelp maybeCommandName = do
  case maybeCommandName of
    Nothing -> do
      outputStrLn $ "Standard commands:"
      outputTabularList $ commandNamesForCategory StandardCommand
      outputStrLn $ "Message digest commands:"
      outputTabularList $ commandNamesForCategory MessageDigestCommand
      outputStrLn $ "Cipher commands:"
      outputTabularList $ commandNamesForCategory CipherCommand
      outputStrLn $ ""
    Just commandName -> do
      case Map.lookup commandName commandTable of
        Nothing -> do
          outputStrLn $ "No command by that name."
          outputStrLn $ ""
        Just (Command _
                      _
                      mandatoryParameters
                      optionalParameters
                      _) -> do
          outputStrLn $ "Usage: " ++ commandName
                        ++ mandatoryParameterDescription
                        ++ optionalParameterDescription
          outputStrLn $ ""
          where
            mandatoryParameterDescription :: String
            mandatoryParameterDescription =
              if null mandatoryParameters
                then ""
                else " " ++ (intercalate " "
                              $ map describeParameter mandatoryParameters)
            optionalParameterDescription :: String
            optionalParameterDescription =
              if null optionalParameters
                 then ""
                 else " " ++ optionalParameterDescription' optionalParameters
            optionalParameterDescription' :: [Parameter] -> String
            optionalParameterDescription' (only:[]) =
              "[" ++ describeParameter only ++ "]"
            optionalParameterDescription' (item:rest) =
              "[" ++ describeParameter item ++ " "
              ++ optionalParameterDescription' rest ++ "]"
            describeParameter :: Parameter -> String
            describeParameter StringParameter = "string"
            describeParameter InputFileParameter = "input-file"
  where
    outputTabularList :: [String] -> InputT IO ()
    outputTabularList items = do
      let lineLoop [] = return ()
          lineLoop items = do
            let here = take 5 items
                rest = drop 5 items
            outputStrLn $ concat $ ["  "]
                                   ++ (map (\item ->
                                              replicate (15 - length item) ' ')
                                           (init here))
                                   ++ [last here]
            case rest of
              [] -> return ()
              _ -> lineLoop rest
      lineLoop items
    commandNamesForCategory :: CommandCategory -> [String]
    commandNamesForCategory category =
      sort $ map (\(Command _ name _ _ _) -> name)
                 $ filter (\(Command foundCategory _ _ _ _) ->
                             category == foundCategory)
                          $ Map.elems commandTable


commandMD5 :: ByteString -> InputT IO ()
commandMD5 input = do
  let output = BS.pack $ MD5.hash $ BS.unpack input
  outputHex output


smartWords :: String -> [String]
smartWords input =
  let (result, _, _) =
        foldl (\(result, inWord, inQuotes) c ->
                 let (newInWord, newInQuotes, shouldCollect) =
                       case (inQuotes, isSpace c, c) of
                         (True, False, '"') -> (True, False, False)
                         (True, _, _) -> (True, True, True)
                         (False, False, '"') -> (True, True, False)
                         (False, False, _) -> (True, False, True)
                         (False, True, _) -> (False, False, False)
                     newResult =
                       if shouldCollect
                         then if inWord
                                then init result ++ [last result ++ [c]]
                                else result ++ [[c]]
                         else result
                 in (newResult, newInWord, newInQuotes))
              ([], False, False)
              input
  in result


outputHex :: ByteString -> InputT IO ()
outputHex bytestring = do
  let toHex :: Word8 -> String
      toHex word = case showHex word "" of
                     all@(c1:c2:[]) -> all
                     c2:[] -> '0':c2:[]
  outputStrLn $ concat $ map toHex $ BS.unpack bytestring
