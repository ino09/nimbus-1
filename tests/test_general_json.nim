# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  unittest, strformat, strutils, sequtils, tables, json, ospaths, times,
  byteutils, ranges/typedranges, nimcrypto/[keccak, hash],
  rlp, eth_trie/[types, memdb], eth_common,
  eth_keys,
  ./test_helpers,
  ../nimbus/[constants, errors],
  ../nimbus/[vm_state, vm_types],
  ../nimbus/utils/header,
  ../nimbus/vm/interpreter,
  ../nimbus/db/[db_chain, state_db]

proc testFixture(fixtures: JsonNode, testStatusIMPL: var TestStatus)

suite "generalstate json tests":
  jsonTest("GeneralStateTests", testFixture)


proc stringFromBytes(x: ByteRange): string =
  result = newString(x.len)
  for i in 0 ..< x.len:
    result[i] = char(x[i])

proc testFixture(fixtures: JsonNode, testStatusIMPL: var TestStatus) =
  var fixture: JsonNode
  for label, child in fixtures:
    fixture = child
    break

  let fenv = fixture["env"]
  var emptyRlpHash = keccak256.digest(rlp.encode("").toOpenArray)
  let header = BlockHeader(
    coinbase: fenv{"currentCoinbase"}.getStr.parseAddress,
    difficulty: fromHex(UInt256, fenv{"currentDifficulty"}.getStr),
    blockNumber: fenv{"currentNumber"}.getHexadecimalInt.u256,
    gasLimit: fenv{"currentGasLimit"}.getHexadecimalInt.GasInt,
    timestamp: fenv{"currentTimestamp"}.getHexadecimalInt.int64.fromUnix,
    stateRoot: emptyRlpHash
    )

  var memDb = newMemDB()
  var vmState = newBaseVMState(header, newBaseChainDB(trieDB memDb))
  var code = "0x60016001016000"
  vmState.mutateStateDB:
    setupStateDB(fixture{"pre"}, db)

  let ftrans = fixture["transaction"]

  # Doesn't matter.
  let toAddress = "0xaaaf5374fce5edbc8e2a8697c15331677e6ebf0b".parseAddress


  # FIXME: can be multiple, but most commonly 1
  doAssert ftrans{"data"}.len >= 1

  # FIXME handle (a) data == [""] and (b) data is (multiple) hex uint256 strings
  # message takes seq[byte], so just concat the hex string results
  # something like reduce(join_seqbytes, map(foo.getStr.hexToSeqBytes, inputseq))
  let rawData = ftrans{"data"}[0].getStr
  let data = (if rawData == "": "0x" else: rawData).hexToSeqByte

  # The pre-existing abstraction here is executeTransaction from vm_state_transaction.nim
  # TODO: flesh out that stub and refactor any code from there there

  # TODO: two sorts of iteration: #1 through EIP150/EIP158/Homestead/etc
  # #2 through transactions
  # TODO: create separate pre-rigged example(s) for CI purposes

  # This will matter when actually executing transactions more
  let message = newMessage(
      # Doesn't matter
      to = toAddress,

      # Doesn't matter; match type most conveniently
      sender = toAddress,

      # FIXME: use new direct int-parsing methods
      # Also in VMTests
      value = cast[uint64](ftrans{"value"}.getHexadecimalInt).u256, # Cast workaround for negative value
      data = data,
      code = code,

      gas = fenv{"currentGasLimit"}.getHexadecimalInt.GasInt,
      gasPrice = ftrans{"gasPrice"}.getHexadecimalInt,

      # See regarding sender.
      options = newMessageOptions(origin=toAddress,
                                  createAddress = toAddress))

  var computation = newBaseComputation(vmState, header.blockNumber, message)
  computation.vmState = vmState
  computation.precompiles = initTable[string, Opcode]()

  var huh = ftrans["secretKey"].getStr
  removePrefix(huh, "0x")
  let privateKey = initPrivateKey(huh)
  echo privateKey
  let publicKey = getPublicKey(privateKey)
  echo publicKey
  #let pkHash = keccak256 publicKey
  #echo pkHash

  # Unlike VMTests, there's no if-no-post-then-error-is-expected condition
  check(not computation.isError)
  if computation.isError:
    echo "Computation error: ", computation.error.info
  let logEntries = computation.getLogEntries()
  if not fixture{"logs"}.isNil:
    discard
  elif logEntries.len > 0:
    checkpoint(&"Got log entries: {logEntries}")
    fail()

  # TODO: do this right
  # though, in general the results per fork aren't usually different, so can lower priority on that aspect
  doAssert "0x" & `$`(vmState.readOnlyStateDB.rootHash).toLowerAscii == fixture["post"]["Byzantium"][0]["hash"].getStr

  # check gasmeter

  let gasMeter = computation.gasMeter
