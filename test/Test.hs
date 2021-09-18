{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Data.Binary (encode, decode)
import Data.TrustChain
import Cropty
import System.Exit (exitFailure)
import Control.Monad (forM_)

requires :: String -> [Bool] -> IO ()
requires msg = mapM_ (uncurry go) . zip [1..] where
  go x y = if y then pure () else putStrLn (msg <> ": " <> show x) >> exitFailure

main :: IO ()
main = do
  privateKey0 <- generatePrivateKey KeySize256
  privateKey1 <- generatePrivateKey KeySize256
  let trustChain0 :: TrustChain [] String = Trustless "Hello"
  trustChain1 <- mkTrustProxy privateKey0 [mkTrustless "Hi", trustChain0]
  trustChain2 <- mkTrustProxy privateKey1 [mkTrustless "Hey", trustChain1]
  let roundTrip f g x = x == f (g x)
  requires "validTrustChain"
    [ validTrustChain trustChain0
    , validTrustChain trustChain1
    , validTrustChain trustChain2
    ]
  requires "claims"
    [ claims trustChain0 == [Claim [] "Hello"]
    , claims trustChain1 == [Claim [privateToPublic privateKey0] "Hi", Claim [privateToPublic privateKey0] "Hello"]
    , claims trustChain2 == [Claim [privateToPublic privateKey1] "Hey", Claim [privateToPublic privateKey1, privateToPublic privateKey0] "Hi", Claim [privateToPublic privateKey1, privateToPublic privateKey0] "Hello"] 
    ]
  requires "encode/decode" $ map (roundTrip decode encode) [trustChain0, trustChain1, trustChain2]
