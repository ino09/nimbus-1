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
  ./test_helpers,
  ../nimbus/[constants, errors, logging],
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
  var code = ""
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
  let data = (if rawData == "": "0xaaaf5374fce5edbc8e2a8697c15331677e6ebf0b" else: rawData).hexToSeqByte

  # of these, only gas seems to be used in
  # https://github.com/status-im/nimbus/blob/master/nimbus/vm/computation.nim
  # and message goes out of lexical scope.
  # To start with, isolate changes here.
  let message = newMessage(
      # Doesn't matter
      to = toAddress,

      # Doesn't matter; match type most conveniently
      sender = toAddress,

      # FIXME: use new direct int-parsing methods
      value = cast[uint64](ftrans{"value"}.getHexadecimalInt).u256, # Cast workaround for negative value
      data = data,

      # Only ever "" here.
      code = code,

      gas = ftrans{"gasLimit"}.getHexadecimalInt,
      gasPrice = ftrans{"gasPrice"}.getHexadecimalInt,

      # See regarding sender.
      options = newMessageOptions(origin=toAddress,
                                  createAddress = toAddress))

  var computation = newBaseComputation(vmState, header.blockNumber, message)
  #[
  computation.vmState = vmState
  computation.precompiles = initTable[string, Opcode]()

  computation.executeOpcodes()

  if not fixture{"post"}.isNil:
    # Success checks
    check(not computation.isError)
    if computation.isError:
      echo "Computation error: ", computation.error.info

    let logEntries = computation.getLogEntries()
    if not fixture{"logs"}.isNil:
      discard
      # TODO hashLogEntries let actualLogsHash = hashLogEntries(logEntries)
      # let expectedLogsHash = fixture{"logs"}.getStr
      # check(expectedLogsHash == actualLogsHash)
    elif logEntries.len > 0:
      checkpoint(&"Got log entries: {logEntries}")
      fail()

    let expectedOutput = fixture{"out"}.getStr
    check(computation.outputHex == expectedOutput)
    let gasMeter = computation.gasMeter

    let expectedGasRemaining = fixture{"gas"}.getHexadecimalInt
    let actualGasRemaining = gasMeter.gasRemaining
    checkpoint(&"Remaining: {actualGasRemaining} - Expected: {expectedGasRemaining}")
    check(actualGasRemaining == expectedGasRemaining or
          computation.code.hasSStore() and
            (actualGasRemaining > expectedGasRemaining and (actualGasRemaining - expectedGasRemaining) mod 15_000 == 0 or
             expectedGasRemaining > actualGasRemaining and (expectedGasRemaining - actualGasRemaining) mod 15_000 == 0))

    if not fixture{"post"}.isNil:
      verifyStateDb(fixture{"post"}, computation.vmState.readOnlyStateDB)
  else:
      # Error checks
      check(computation.isError)
      # TODO postState = fixture{"pre"}
  ]#
