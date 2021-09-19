{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
module Data.TrustChain
  ( 
    -- * Trust Chains
    TrustChain (..)
  , validTrustChain
  , mkTrustProxy
  , mkTrustless
    -- * White Lists
  , Whitelist (..)
  , filterByWhitelist
    -- * Claims
  , Claim (..)
  , claims
    -- * Index and Merge
  , assignments 
    -- * Inconsistencies
  , Inconsistency (..)
    -- * Re-Exports from Cropty
  , PublicKey
  , PrivateKey
  , Signed(..)
    -- * Re-Exports from Data.Merge
  , Merge
  ) where

import Data.Text (Text)
import Data.Set (Set)
import Data.Typeable (Typeable)
import qualified Data.Set as Set
import Data.Map (Map)
import Data.Foldable (toList)
import qualified Data.Map.Strict as Map
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Functor.Identity (Identity (..))
import Data.Binary (Binary (..))
import qualified Data.Binary as Binary
import GHC.Generics (Generic)
import Data.Semigroup (All(All, getAll))
import Cropty
import Data.Merge

encode :: Binary a => a -> ByteString
encode a = LBS.toStrict $ Binary.encode a

-- | A tree of trust of the given shape, where each internal node of the
-- tree is signed by potentially different keys. @TrustChain Identity a@
-- is a linear signature chain, whereas @TrustChain NonEmpty a@ is a tree
-- shaped trust chain. We can keep track of metadata at each internal
-- node of any structure using @TrustChain (Compose ((,) metadata) f) a@.
--
-- For those who are familiar with the free monad, you can think of this
-- as a free monad where the internal nodes are signed by differing parties.
data TrustChain f a =
    Trustless a
  | TrustProxy (Signed (f (TrustChain f a)))
  deriving (Generic, Typeable)

deriving instance (Show a, forall a. Show a => Show (f a)) => Show (TrustChain f a)
deriving instance (Read a, forall a. Read a => Read (f a)) => Read (TrustChain f a)
deriving instance (Binary a, Binary (f (TrustChain f a))) => Binary (TrustChain f a)

instance Eq a => Eq (TrustChain f a) where
  Trustless a == Trustless a' = a == a'
  Trustless _ == TrustProxy _ = False
  TrustProxy _ == Trustless _ = False
  TrustProxy s == TrustProxy s' = signature s == signature s' && signedBy s == signedBy s' && signedEncoded s == signedEncoded s'

instance Ord a => Ord (TrustChain f a) where
  compare (Trustless a) (Trustless a') = compare a a'
  compare (Trustless a) _ = GT
  compare (TrustProxy a) (Trustless _) = LT
  compare (TrustProxy s) (TrustProxy s') =
       compare (signature s) (signature s')
    <> compare (signedBy s) (signedBy s')
    <> compare (signedEncoded s) (signedEncoded s')

-- | A set of 'PublicKey's we accept information from.
newtype Whitelist = Whitelist { unWhitelist :: Set PublicKey }
  deriving (Eq, Ord, Show, Read, Generic, Typeable, Binary)

-- | Strips out all elements of the chain which aren't rooted by someone in
-- our whitelist, creating a forest of 'TrustChain's instead of a single one.
filterByWhitelist :: Foldable f => Whitelist -> TrustChain f a -> [TrustChain f a]
filterByWhitelist w@(Whitelist ws) (Trustless a) = []
filterByWhitelist w@(Whitelist ws) (TrustProxy s) = if signedBy s `Set.member` ws then [TrustProxy s] else toList (signed s) >>= filterByWhitelist w

-- | Check that the trust chain has been legitimately signed. Once you receive
-- 'True' from this function, you can be certain that all of the 'Signed'
-- types within are truly correct.
validTrustChain :: (Binary a, Binary (f (TrustChain f a)), Foldable f) => TrustChain f a -> Bool
validTrustChain (Trustless _) = True
validTrustChain (TrustProxy s) = verifySigned s && getAll (foldMap (All . validTrustChain) (signed s))

-- | Extend the trust chain with new subchains and new items.
mkTrustProxy ::
  ( Traversable f
  , Binary (f (TrustChain f a))
  )
  => PrivateKey
  -> f (TrustChain f a)
  -> IO (TrustChain f a)
mkTrustProxy privateKey layer = TrustProxy <$> mkSigned privateKey layer

-- | Make a basic, trustless trust chain.
mkTrustless :: a -> TrustChain f a
mkTrustless = Trustless

-- |
-- A path through the trust chain.
data Claim a = Claim [PublicKey] a
  deriving (Eq, Ord, Typeable, Generic, Binary)

-- |
-- An inconsistency with the various accounts in the trust chain
data Inconsistency e a =
    IncompatibleClaim e (Claim a) [Claim a]
  deriving (Eq, Ord, Typeable, Generic, Binary)

-- |
-- Extract all of the claims from the trust chain.
claims :: Foldable f => TrustChain f a -> [Claim a]
claims = \case
  Trustless a -> [Claim [] a]
  TrustProxy s -> (\(Claim ps a) -> Claim (signedBy s : ps) a) <$> foldMap claims (signed s)

-- | 
-- Extract all of the assignments from the trust chain, unifying information contained
-- within them. This is where we might find potential inconsistencies.
assignments :: Ord k => (a -> k) -> Merge e a a -> [Claim a] -> Either (Inconsistency e a) (Map k a)
assignments getKey f cs = go Map.empty cs where
  go as [] = Right (Map.map fst as)
  go as (Claim ps a : xxs) =
    case Map.lookup (getKey a) as of
      Just (a', pss) -> case runMerge f a a' of
        Success a'' -> go (Map.adjust (\_ -> (a'', Claim ps a : pss)) (getKey a) as) xxs
        Error e -> Left (IncompatibleClaim e (Claim ps a) pss)
      Nothing -> go (Map.insert (getKey a) (a, [Claim ps a]) as) xxs
