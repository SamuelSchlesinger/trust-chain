{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
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
  , claimants
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

import Data.Set (Set)
import Data.Typeable (Typeable)
import qualified Data.Set as Set
import Data.Map (Map)
import Data.Foldable (toList)
import qualified Data.Map.Strict as Map
import Data.Binary (Binary (..))
import GHC.Generics (Generic)
import Data.Semigroup (All(All, getAll))
import Cropty
import Data.Merge

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

deriving instance (Show a, Show (f (TrustChain f a))) => Show (TrustChain f a)
deriving instance (Read a, Read (f (TrustChain f a))) => Read (TrustChain f a)
deriving instance (Binary a, Binary (f (TrustChain f a))) => Binary (TrustChain f a)

instance Eq a => Eq (TrustChain f a) where
  Trustless a == Trustless a' = a == a'
  Trustless _ == TrustProxy _ = False
  TrustProxy _ == Trustless _ = False
  TrustProxy s == TrustProxy s' = s == s'

instance Ord a => Ord (TrustChain f a) where
  compare (Trustless a) (Trustless a') = compare a a'
  compare (Trustless _) _ = GT
  compare (TrustProxy _) (Trustless _) = LT
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
filterByWhitelist _ (Trustless _) = []
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
  deriving (Eq, Ord, Show, Read, Typeable, Generic, Binary)

-- |
-- An inconsistency with the various accounts in the trust chain
data Inconsistency e a =
    IncompatibleClaim e (Claim a) [Claim a]
  deriving (Eq, Ord, Show, Read, Typeable, Generic, Binary)

-- |
-- Extract all of the claims from the trust chain.
claims :: Foldable f => TrustChain f a -> [Claim a]
claims = \case
  Trustless a -> [Claim [] a]
  TrustProxy s -> (\(Claim ps a) -> Claim (signedBy s : ps) a) <$> foldMap claims (signed s)

-- |
-- Index the claimants by what they're claiming, using the given indexing function.
--
-- The mental model here should something like @k = PublicKey@ and @a = Person@. What
-- we're doing is figuring out, for every different 'PublicKey' contained in the @Trustless@
-- node in our 'TrustChain', all of the different variations and series of signatures which lead up to those variations (along with who assented to those accounts).
--
-- There is no 'Merge'ing here, in particular. This is the way to splay out all of the different realities and the sequences of
-- 'PublicKey' which signed that particular variation (at one time or another).
claimants :: (Ord k, Ord a) => (a -> k) -> [Claim a] -> Map k (Map a (Set [PublicKey]))
claimants i cs = Map.fromListWith (Map.unionWith (<>)) [ (k, Map.singleton a (Set.singleton ps)) | Claim ps a <- cs, let k = i a ]

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
