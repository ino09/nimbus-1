# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  constants, errors, eth_common, rlp, eth_common/eth_types

type
  Account* = object
    nonce*:             AccountNonce

    # XXX: RLP seems not to output UInt256 properly in this situation
    # Can't be merged to master
    #balance*:           UInt256
    balance*:           uint64

    storageRoot*:       Hash256
    codeHash*:          Hash256

proc newAccount*(nonce: AccountNonce = 0, balance: uint64 = 0): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = BLANK_ROOT_HASH
  result.codeHash = EMPTY_SHA3
