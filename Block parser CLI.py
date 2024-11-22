import subprocess
import json
from datetime import datetime, timezone
import hashlib
import base58

# Configuration
bitcoin_cli = r'"D:\Program Files 2\Bitcoin\daemon\bitcoin-cli"'
conf_file = r'D:\Program Files 2\Bitcoin\bitcoin.conf'
command_base = f'{bitcoin_cli} -conf="{conf_file}"'

# Start from a specific block height
start_height = 0  # Set your desired start block height here


# Function to fetch block hash by height
def get_block_hash_by_height(height):
    try:
        command = f'{command_base} getblockhash {height}'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            print(f"Error fetching block hash for height {height}: {result.stderr}")
            return None
        return result.stdout.strip()
    except Exception as e:
        print(f"Exception occurred while fetching block hash for height {height}: {e}")
        return None


# Function to fetch block details
def get_block(block_hash):
    try:
        command = f'{command_base} getblock {block_hash} 2'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            print(f"Error fetching block {block_hash}: {result.stderr}")
            return None
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Exception occurred while fetching block {block_hash}: {e}")
        return None


# Function to convert a public key to a Bitcoin address
def pubkey_to_address(pubkey_hex):
    try:
        # Step 1: SHA-256
        sha256_result = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()

        # Step 2: RIPEMD-160
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_result)
        ripemd160_result = ripemd160.digest()

        # Step 3: Add network prefix (0x00 for Bitcoin mainnet)
        network_prefix = b'\x00'  # Mainnet
        prefixed_key = network_prefix + ripemd160_result

        # Step 4: Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(prefixed_key).digest()).digest()[:4]

        # Step 5: Concatenate and Base58 encode
        address_bytes = prefixed_key + checksum
        address = base58.b58encode(address_bytes).decode('utf-8')
        return address
    except Exception:
        return "Invalid Public Key"


# Function to extract and print block details
def print_block_details(block_data):
    height = block_data.get("height")
    block_hash = block_data.get("hash")
    time_utc = datetime.fromtimestamp(block_data.get("time"), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    next_block_hash = block_data.get("nextblockhash", "N/A")
    txs = block_data.get("tx", [])

    # Print block information only once
    print(f"\n\n\n************************")
    print(f"Block Height: {height}")
    print(f"Block Hash: {block_hash}")
    print(f"************************\n")


    # Iterate over each transaction
    for tx in txs:
        txid = tx.get("txid")
        inputs = tx.get("vin", [])
        outputs = tx.get("vout", [])

        # Iterate over inputs (sender addresses)
        sender_addresses = []
        for inp in inputs:
            # Look for SegWit or legacy address extraction in the input
            if "txinwitness" in inp:
                # For SegWit transactions, the sender address is not explicitly present in the `scriptSig`
                # We extract witness data and check if it's a valid SegWit address
                witness_data = inp["txinwitness"]
                if witness_data:
                    # SegWit address extraction (assuming witness contains a P2WPKH address)
                    sender_addresses.append(f"SegWit Address: {witness_data[-1]}")
            elif "scriptSig" in inp and "asm" in inp["scriptSig"]:
                # For legacy transactions, extract the address from the scriptSig
                asm = inp["scriptSig"]["asm"]
                pubkey_hex = asm.split()[-1]  # Assume it's the public key (needs to be derived into an address)
                sender_address = pubkey_to_address(pubkey_hex)
                sender_addresses.append(sender_address)

        # For each output, determine the receiver address
        for out in outputs:
            value = out.get("value", 0)
            script_pub_key = out.get("scriptPubKey", {})

            # Try to fetch the address first
            address = script_pub_key.get("address")

            # If address field is not available, calculate it from the public key
            if not address:
                pubkey_hex = script_pub_key.get("asm", "").split()[0] if "asm" in script_pub_key else None
                address = pubkey_to_address(pubkey_hex) if pubkey_hex else "N/A"

            # Format the value to avoid scientific notation
            formatted_value = f"{value:.8f}"  # Show the value with 8 decimal places

            # Print Transaction Details
            print(f"    Time: {time_utc}")
            print(f"    Amount: {formatted_value} BTC")
            # Print sender addresses (if any)
            if sender_addresses:
                print(f"    Sender Addresses: {', '.join(sender_addresses)}")
            print(f"    Receive Address: {address}")
            print(f"    TXID: {txid}")
            print("---")


current_block_hash = get_block_hash_by_height(start_height)

if not current_block_hash:
    print(f"Unable to fetch block hash for height {start_height}.")
else:
    # Iterate through blocks starting from the specified height
    for i in range(3):  # Change the range to process more or fewer blocks
        #print(f"Fetching block at height {start_height + i}")
        block_data = get_block(current_block_hash)
        if block_data is None:
            break

        # Print the block details
        print_block_details(block_data)

        # Get the next block hash
        current_block_hash = block_data.get("nextblockhash")
        if not current_block_hash:
            print("No more blocks found.")
            break
