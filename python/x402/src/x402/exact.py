import time
import secrets
from typing import Dict, Any, Union, TYPE_CHECKING
from typing_extensions import (
    TypedDict,
)  # use `typing_extensions.TypedDict` instead of `typing.TypedDict` on Python < 3.12
from eth_account import Account
from x402.encoding import safe_base64_encode, safe_base64_decode
from x402.types import (
    PaymentRequirements,
)
from x402.chains import get_chain_id
import json

if TYPE_CHECKING:
    from pysui import SyncClient
    from pysui.sui.sui_builders.get_builders import GetCoins

try:
    from pysui import SyncClient
    from pysui.sui.sui_builders.get_builders import GetCoins
    HAS_PYSUI = True
except ImportError:
    HAS_PYSUI = False


def create_nonce() -> bytes:
    """Create a random 32-byte nonce for authorization signatures."""
    return secrets.token_bytes(32)


def prepare_payment_header(
    account: Union[Account, "SyncClient"], x402_version: int, payment_requirements: PaymentRequirements
) -> Dict[str, Any]:
    """Prepare an unsigned payment header with transaction data ready for signing.
    
    Dispatches to network-specific preparation methods.
    """
    network = payment_requirements.network.lower()
    
    if network in ['sui', 'sui-testnet']:
        if not HAS_PYSUI:
            raise ImportError("pysui package is required for Sui network support. Install it with: uv add pysui")
        return _prepare_payment_header_sui(account, x402_version, payment_requirements)
    else:
        return _prepare_payment_header_evm(account, x402_version, payment_requirements)


def _prepare_payment_header_evm(
    account: Account, x402_version: int, payment_requirements: PaymentRequirements
) -> Dict[str, Any]:
    """Prepare an unsigned payment header for EVM networks.
    
    Creates the authorization structure that will be signed.
    """
    nonce = create_nonce()
    valid_after = str(int(time.time()) - 60)  # 60 seconds before
    valid_before = str(int(time.time()) + payment_requirements.max_timeout_seconds)

    return {
        "x402Version": x402_version,
        "scheme": payment_requirements.scheme,
        "network": payment_requirements.network,
        "payload": {
            "signature": None,
            "authorization": {
                "from": account.address,
                "to": payment_requirements.pay_to,
                "value": payment_requirements.max_amount_required,
                "validAfter": valid_after,
                "validBefore": valid_before,
                "nonce": nonce,
            },
        },
    }


def _prepare_payment_header_sui(
    client: "SyncClient", x402_version: int, payment_requirements: PaymentRequirements
) -> Dict[str, Any]:
    """Prepare an unsigned payment header for Sui networks.
    
    Builds the transaction and returns it ready for signing.
    """
    if not HAS_PYSUI:
        raise ImportError("pysui package is required for Sui network support")
    
    # Get sender address from the client's active address
    sender = client.config.active_address
    
    # Create a transfer transaction with initial sender
    txn = client.transaction(initial_sender=sender)

    # Get coins of the specified type for the sender
    coin_type = payment_requirements.asset
    amount_required = int(payment_requirements.max_amount_required)

    # If the coin type is SUI, we can use the gas coin directly
    if coin_type == "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI":
        # Use gas coin for SUI transfers
        coin_to_send = txn.split_coin(
            coin=txn.gas,
            amounts=[amount_required]
        )
    else:
        # For other coin types, we need to get coins of that type
        # Fetch the type coins with paging
        coin_data = []
        q_res = client.execute(GetCoins(owner=sender, coin_type=coin_type))
        while q_res.is_ok() and q_res.result_data.data:
            coin_data.extend(q_res.result_data.data)
            if q_res.result_data.next_cursor:
                q_res = client.execute(
                    GetCoins(
                        owner=sender,
                        coin_type=coin_type,
                        cursor=q_res.result_data.next_cursor,
                    )
                )
            else:
                break
                
        if not coin_data:
            raise Exception(f"No coins of type {coin_type} found for address {sender}")

        # Check if total balance meets requirement
        total_balance = sum(int(coin.balance) for coin in coin_data)
        if total_balance < amount_required:
            raise Exception(
                f"Insufficient balance. Required: {amount_required}, Available: {total_balance}"
            )
        
        # First see if there is one coin that satisfies
        sufficient_coin = next(
            (coin for coin in coin_data if int(coin.balance) >= amount_required),
            None,
        )
        
        if sufficient_coin:
            # Use the coin that has enough balance and split what we need
            coin_to_send = txn.split_coin(
                coin=sufficient_coin,
                amounts=[amount_required]
            )
        else:
            # Need to merge coins first
            target_coin = coin_data[0]
            # Merge other coins into the target
            txn.merge_coins(merge_to=target_coin, merge_from=coin_data[1:])
            # Split the required amount from the merged coin
            coin_to_send = txn.split_coin(
                coin=target_coin,
                amounts=[amount_required]
            )

    # Transfer the coin to the recipient
    from pysui.sui.sui_types import SuiAddress
    txn.transfer_objects(
        transfers=[coin_to_send],
        recipient=SuiAddress(payment_requirements.pay_to)
    )

    # Build the transaction to get the bytes (but don't sign yet)
    base64_tx_bytes = txn.deferred_execution()
    
    return {
        "x402Version": x402_version,
        "scheme": payment_requirements.scheme,
        "network": payment_requirements.network,
        "payload": {
            "transaction": base64_tx_bytes,  # Base64 encoded transaction bytes
            "signature": None,  # Will be added during signing
        },
    }


class PaymentHeader(TypedDict):
    x402Version: int
    scheme: str
    network: str
    payload: dict[str, Any]


def sign_payment_header(
    account: Union[Account, "SyncClient"], payment_requirements: PaymentRequirements, header: PaymentHeader
) -> str:
    """Sign a payment header using the appropriate method based on the network.

    Args:
        account: Either an eth_account.Account for EVM networks or pysui.SyncClient for Sui networks
        payment_requirements: The payment requirements
        header: Pre-built unsigned header from prepare_payment_header

    Returns:
        Base64 encoded payment header string
    """
    network = payment_requirements.network.lower()

    # Check if it's a Sui network
    if network in ['sui', 'sui-testnet']:
        if not HAS_PYSUI:
            raise ImportError("pysui package is required for Sui network support. Install it with: uv add pysui")
        if not isinstance(account, SyncClient):
            raise TypeError(f"Sui networks require a pysui.SyncClient instance, got {type(account)}")
        return _sign_payment_header_sui(account, header)
    else:
        # Default to EVM signing for all other networks
        if not isinstance(account, Account):
            raise TypeError(f"EVM networks require an eth_account.Account instance, got {type(account)}")
        return _sign_payment_header_evm(account, payment_requirements, header)


def _sign_payment_header_evm(
    account: Account, payment_requirements: PaymentRequirements, header: PaymentHeader
) -> str:
    """Sign a payment header for EVM networks using the account's private key."""
    try:
        auth = header["payload"]["authorization"]

        nonce_bytes = bytes.fromhex(auth["nonce"])

        typed_data = {
            "types": {
                "TransferWithAuthorization": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "validAfter", "type": "uint256"},
                    {"name": "validBefore", "type": "uint256"},
                    {"name": "nonce", "type": "bytes32"},
                ]
            },
            "primaryType": "TransferWithAuthorization",
            "domain": {
                "name": payment_requirements.extra["name"],
                "version": payment_requirements.extra["version"],
                "chainId": int(get_chain_id(payment_requirements.network)),
                "verifyingContract": payment_requirements.asset,
            },
            "message": {
                "from": auth["from"],
                "to": auth["to"],
                "value": int(auth["value"]),
                "validAfter": int(auth["validAfter"]),
                "validBefore": int(auth["validBefore"]),
                "nonce": nonce_bytes,
            },
        }

        signed_message = account.sign_typed_data(
            domain_data=typed_data["domain"],
            message_types=typed_data["types"],
            message_data=typed_data["message"],
        )
        signature = signed_message.signature.hex()
        if not signature.startswith("0x"):
            signature = f"0x{signature}"

        header["payload"]["signature"] = signature

        header["payload"]["authorization"]["nonce"] = f"0x{auth['nonce']}"

        encoded = encode_payment(header)
        return encoded
    except Exception:
        raise


def _sign_payment_header_sui(
    client: "SyncClient", header: PaymentHeader
) -> str:
    """Sign a payment header for Sui networks using pysui client.

    Takes the prepared transaction bytes and adds the signature.
    """
    if not HAS_PYSUI:
        raise ImportError("pysui package is required for Sui network support")

    try:
        # Get the transaction bytes from the prepared header
        base64_tx_bytes = header["payload"]["transaction"]
        
        # We need to recreate a transaction to get its signer block
        # since we can't serialize the transaction object itself
        temp_txn = client.transaction(initial_sender=client.config.active_address)
        
        # Get signature using the transaction's signer block
        signature = (
            temp_txn.signer_block.get_signatures(client=client, tx_bytes=base64_tx_bytes)
            .array[0]
            .signature
        )

        # Update the header with the signature
        header["payload"]["signature"] = signature

        # Encode and return
        return encode_payment(header)

    except Exception as e:
        raise Exception(f"Failed to sign Sui payment header: {str(e)}") from e


def encode_payment(payment_payload: Dict[str, Any]) -> str:
    """Encode a payment payload into a base64 string, handling HexBytes and other non-serializable types."""
    from hexbytes import HexBytes

    def default(obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "hex"):
            return obj.hex()
        raise TypeError(
            f"Object of type {obj.__class__.__name__} is not JSON serializable"
        )

    return safe_base64_encode(json.dumps(payment_payload, default=default))


def decode_payment(encoded_payment: str) -> Dict[str, Any]:
    """Decode a base64 encoded payment string back into a PaymentPayload object."""
    return json.loads(safe_base64_decode(encoded_payment))
