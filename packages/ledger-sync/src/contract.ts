/**
 * Contract address encoding inside signed payloads (LEDGER-SYNC.md section 3).
 *
 *   contract = XDR(ScVal::Address(ScAddress::Contract(contractId)))
 *            = u32BE(SCV_ADDRESS = 18) || u32BE(SC_ADDRESS_TYPE_CONTRACT = 1) || contractId (32)
 *
 * 40 bytes in total, the value `Address::to_xdr(&env)` returns for a contract
 * address in the Soroban SDK. Binding the contract ID into every payload
 * prevents replay across deployments, and therefore across networks, since a
 * contract ID commits to the network passphrase.
 */

import { decodeContractAddress } from '@keptex/stellar-root'

import { concatBytes, u32BE } from './bytes.js'
import { LedgerSyncError } from './errors.js'

/** XDR discriminant of `ScVal::Address`. */
export const SCV_ADDRESS = 18
/** XDR discriminant of `ScAddress::Contract`. */
export const SC_ADDRESS_TYPE_CONTRACT = 1
/** Length of the encoded contract `ScVal`. */
export const CONTRACT_SCVAL_LENGTH = 40

/** A contract, as a `C...` strkey or as its raw 32-byte contract ID. */
export type ContractRef = string | Uint8Array

/** Resolve a contract reference to its 32-byte contract ID (a fresh copy). */
export function contractIdOf(contract: ContractRef): Uint8Array {
  if (typeof contract === 'string') {
    try {
      return decodeContractAddress(contract)
    } catch (err) {
      throw new LedgerSyncError(
        `Invalid contract address: ${err instanceof Error ? err.message : String(err)}`,
        'INVALID_CONTRACT',
      )
    }
  }
  if (contract instanceof Uint8Array && contract.length === 32) {
    return new Uint8Array(contract)
  }
  throw new LedgerSyncError(
    'A contract must be a C... address or a 32-byte contract ID',
    'INVALID_CONTRACT',
  )
}

/** The 40-byte XDR `ScVal` of a contract address. */
export function encodeContractScVal(contract: ContractRef): Uint8Array {
  return concatBytes(u32BE(SCV_ADDRESS), u32BE(SC_ADDRESS_TYPE_CONTRACT), contractIdOf(contract))
}
