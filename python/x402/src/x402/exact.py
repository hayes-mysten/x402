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
    from pysui.sui.sui_txn import SyncTransaction
    from pysui.sui.sui_types import SuiAddress
    from pysui.sui.sui_builders import GetCoins

try:
    from pysui import SyncClient
    from pysui.sui.sui_txn import SyncTransaction
    from pysui.sui.sui_types import SuiAddress
    from pysui.sui.sui_builders import GetCoins
    HAS_PYSUI = True
except ImportError:
    HAS_PYSUI = False


def create_nonce() -> bytes:
    """Create a random 32-byte nonce for authorization signatures."""
    return secrets.token_bytes(32)


def prepare_payment_header(
    sender_address: str, x402_version: int, payment_requirements: PaymentRequirements
) -> Dict[str, Any]:
    """Prepare an unsigned payment header with sender address, x402 version, and payment requirements."""
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
                "from": sender_address,
                "to": payment_requirements.pay_to,
                "value": payment_requirements.max_amount_required,
                "validAfter": valid_after,
                "validBefore": valid_before,
                "nonce": nonce,
            },
        },
    }


class PaymentHeader(TypedDict):
    x402Version: int
    scheme: str
    network: str
    payload: dict[str, Any]


def sign_payment_header(
    account: Union[Account, "SyncClient"], payment_requirements: PaymentRequirements, header: PaymentHeader = None, x402_version: int = 1
) -> str:
    """Sign a payment header using the appropriate method based on the network.

    Args:
        account: Either an eth_account.Account for EVM networks or pysui.SyncClient for Sui networks
        payment_requirements: The payment requirements
        header: Optional pre-built header (used for EVM networks)
        x402_version: The version of the X402 protocol to use (default: 1)

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
        return _sign_payment_header_sui(account, payment_requirements, x402_version)
    else:
        # Default to EVM signing for all other networks
        if not isinstance(account, Account):
            raise TypeError(f"EVM networks require an eth_account.Account instance, got {type(account)}")
        if header is None:
            # Create a header if not provided
            header = prepare_payment_header(
                account.address, x402_version, payment_requirements
            )
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
    client: "SyncClient", payment_requirements: PaymentRequirements, x402_version: int
) -> str:
    """Sign a payment header for Sui networks using pysui client.

    This follows the TypeScript implementation pattern from typescript/packages/x402/src/schemes/exact/sui/client.ts
    """
    if not HAS_PYSUI:
        raise ImportError("pysui package is required for Sui network support")

    try:
        # Create a transfer transaction
        txn = SyncTransaction(client=client)

        # Get sender address from the client's active address
        sender = client.active_address

        # Get coins of the specified type for the sender
        coin_type = payment_requirements.asset
        amount_required = int(payment_requirements.max_amount_required)

        # If the coin type is SUI, we can use the gas coin directly
        if coin_type == "0x2::sui::SUI" or coin_type == "sui":
            # Use gas coin for SUI transfers
            coin_to_send = txn.split_coin(
                coin=txn.gas,
                amounts=[amount_required]
            )
        else:
            # For other coin types, we need to get coins of that type
            # Query for coins of the specified type owned by the sender
            get_coins_result = client.execute(
                GetCoins(
                    owner=sender,
                    coin_type=coin_type
                )
            )

            if not get_coins_result.result or not get_coins_result.result.data:
                raise Exception(f"No coins of type {coin_type} found for address {sender}")

            coins = get_coins_result.result.data

            # Calculate total balance
            total_balance = sum(int(coin.balance) for coin in coins)

            if total_balance < amount_required:
                raise Exception(f"Insufficient balance. Required: {amount_required}, Available: {total_balance}")

            # Need to merge coins first
            # Take the first coin as the target
            target_coin = coins[0]

            # Merge other coins into the target
            if len(coins) > 1:
                merge_coins = [coin.coinObjectId for coin in coins[1:]]
                txn.merge_coins(
                    coin=target_coin.coinObjectId,
                    coins_to_merge=merge_coins
                )

            # Now split the required amount from the merged coin
            coin_to_send = txn.split_coin(
                coin=target_coin.coinObjectId,
                amounts=[amount_required]
            )

        # Transfer the coin to the recipient
        txn.transfer_objects(
            transfers=[coin_to_send],
            recipient=SuiAddress(payment_requirements.pay_to)
        )

        # Build and sign the transaction - this returns the transaction bytes and signature
        result = client.execute_no_sign(txn)

        if not result.is_ok():
            raise Exception(f"Failed to execute transaction: {result.error}")

        tx_bytes = result.data.serialize()
        signed_tx = client.sign_for_execution(tx_bytes)

        # Create the payment payload matching TypeScript structure
        payment_payload = {
            "scheme": payment_requirements.scheme,
            "network": payment_requirements.network,
            "x402Version": x402_version,
            "payload": {
                "transaction": signed_tx.tx_bytes,  # Base64 encoded transaction bytes
                "signature": signed_tx.signature,    # Base64 encoded signature
            }
        }

        # Encode and return
        return encode_payment(payment_payload)

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
