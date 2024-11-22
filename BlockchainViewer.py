# version 1.0 - 05:13 23/11/24
import struct
import binascii
from hashlib import sha256
from base58 import b58encode
from datetime import datetime, timezone
from collections import defaultdict


def read_varint(f):
    """Reads a variable-length integer."""
    value = f.read(1)[0]
    if value < 0xfd:
        return value
    elif value == 0xfd:
        return struct.unpack('<H', f.read(2))[0]
    elif value == 0xfe:
        return struct.unpack('<I', f.read(4))[0]
    else:
        return struct.unpack('<Q', f.read(8))[0]


def read_block(file_path):
    """Reads a Bitcoin block from a file."""
    with open(file_path, 'rb') as f:
        f.read(4)  # Magic number
        block_size = struct.unpack('<I', f.read(4))[0]
        block_header = f.read(80)  # Block header
        timestamp = struct.unpack('<I', block_header[68:72])[0]
        transaction_count = read_varint(f)
        transactions = []
        for _ in range(transaction_count):
            transactions.append(read_transaction(f))
        return transactions, timestamp


def read_transaction(f):
    """Reads a single Bitcoin transaction."""
    version = struct.unpack('<I', f.read(4))[0]
    input_count = read_varint(f)
    inputs = [read_input(f) for _ in range(input_count)]
    output_count = read_varint(f)
    outputs = [read_output(f) for _ in range(output_count)]
    lock_time = struct.unpack('<I', f.read(4))[0]
    return {'version': version, 'inputs': inputs, 'outputs': outputs, 'lock_time': lock_time}


def read_input(f):
    """Reads a transaction input."""
    previous_output = f.read(32)[::-1]  # Reverse bytes for TXID
    index = struct.unpack('<I', f.read(4))[0]
    script_length = read_varint(f)
    script = f.read(script_length)
    sequence = struct.unpack('<I', f.read(4))[0]
    return {'previous_output': previous_output, 'index': index, 'script': script, 'sequence': sequence}


def read_output(f):
    """Reads a transaction output."""
    value = struct.unpack('<Q', f.read(8))[0]  # Value in satoshis
    script_length = read_varint(f)
    script = f.read(script_length)
    return {'value': value, 'script': script}


def serialize_transaction(tx):
    """Serializes a transaction back into its raw form for TXID calculation."""
    serialized = struct.pack('<I', tx['version'])  # Version
    serialized += write_varint(len(tx['inputs']))  # Number of inputs
    for txin in tx['inputs']:
        serialized += txin['previous_output'][::-1]  # Previous TXID (reversed)
        serialized += struct.pack('<I', txin['index'])  # Output index
        serialized += write_varint(len(txin['script']))  # Script length
        serialized += txin['script']  # Script
        serialized += struct.pack('<I', txin['sequence'])  # Sequence number
    serialized += write_varint(len(tx['outputs']))  # Number of outputs
    for txout in tx['outputs']:
        serialized += struct.pack('<Q', txout['value'])  # Value in satoshis
        serialized += write_varint(len(txout['script']))  # Script length
        serialized += txout['script']  # Script
    serialized += struct.pack('<I', tx['lock_time'])  # Lock time
    return serialized


def write_varint(value):
    """Writes a variable-length integer."""
    if value < 0xfd:
        return struct.pack('B', value)
    elif value <= 0xffff:
        return b'\xfd' + struct.pack('<H', value)
    elif value <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', value)
    else:
        return b'\xff' + struct.pack('<Q', value)


def get_address_from_script(script):
    """Converts P2PKH, P2SH, P2WPKH, and P2WPKH-nested-P2SH scripts to Bitcoin addresses."""
    try:
        if len(script) > 0:
            # P2PKH (Pay-to-PubKey-Hash)
            if script[0] == 0x76:  # OP_DUP (start of a standard P2PKH script)
                pubkey_hash = script[3:23]  # Extract hash160 (20 bytes)
                versioned_payload = b'\x00' + pubkey_hash  # Prepend mainnet version byte
                checksum = sha256(sha256(versioned_payload).digest()).digest()[:4]
                address = b58encode(versioned_payload + checksum).decode('utf-8')
                return address

            # P2SH (Pay-to-Script-Hash)
            elif script[0] == 0xa9:  # OP_HASH160 (start of P2SH)
                script_hash = script[1:21]  # Extract hash160 (20 bytes)
                versioned_payload = b'\x05' + script_hash  # Prepend mainnet version byte
                checksum = sha256(sha256(versioned_payload).digest()).digest()[:4]
                address = b58encode(versioned_payload + checksum).decode('utf-8')
                return address

            # P2WPKH (Pay-to-Witness-PubKey-Hash) - Native SegWit
            elif script[0] == 0x00 and script[1] == 0x14:  # OP_0 OP_DATA_20
                pubkey_hash = script[2:22]  # Extract 20-byte public key hash
                address = 'bc1' + b58encode(pubkey_hash).decode('utf-8')
                return address

            # P2WPKH-nested-P2SH (SegWit wrapped in P2SH)
            elif script[0] == 0xa9 and script[1] == 0x14:  # OP_HASH160 OP_DATA_20
                script_hash = script[2:22]  # Extract 20-byte script hash
                versioned_payload = b'\x05' + script_hash  # Prepend P2SH version byte
                checksum = sha256(sha256(versioned_payload).digest()).digest()[:4]
                address = b58encode(versioned_payload + checksum).decode('utf-8')
                return address

        return None  # Return None if it's not a recognized address type
    except Exception as e:
        print(f"Error decoding script: {e}")
        return None




def resolve_sender_address(input_data, utxo_map):
    """Resolves the sender address by looking up the previous transaction output."""
    prev_txid = input_data['previous_output']
    prev_index = input_data['index']
    prev_outputs = utxo_map.get(prev_txid)
    if prev_outputs and prev_index < len(prev_outputs):
        prev_output = prev_outputs[prev_index]
        return get_address_from_script(prev_output['script'])
    return None


def build_utxo_map(transactions):
    """Builds a map of unspent transaction outputs."""
    utxo_map = defaultdict(list)
    for tx in transactions:
        serialized_tx = serialize_transaction(tx)
        txid = sha256(sha256(serialized_tx).digest()).digest()[::-1]
        utxo_map[txid] = tx['outputs']
    return utxo_map


def calculate_txid(tx):
    """Calculates the transaction ID (TXID)."""
    serialized_tx = serialize_transaction(tx)
    txid = sha256(sha256(serialized_tx).digest()).digest()[::-1]
    return binascii.hexlify(txid).decode('utf-8')


def parse_block(block, timestamp, utxo_map):
    """Parses transactions from a block."""
    transactions_info = []
    for tx in block:
        txid = calculate_txid(tx)  # Calculate the transaction hash (TXID)
        sender_address = None
        if tx['inputs']:
            sender_address = resolve_sender_address(tx['inputs'][0], utxo_map)
        for i, output in enumerate(tx['outputs']):
            receiver_address = get_address_from_script(output['script'])
            amount = f"{output['value'] / 1e8:.8f}"  # Convert satoshis to BTC
            date = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            transactions_info.append({
                'TXID': txid,
                'Date': date,
                'Amount': amount,
                'Sender Address': sender_address,
                'Receiver Address': receiver_address
            })
    return transactions_info


# File path to the Bitcoin block file
block_file = r'D:\Program Files 2\Bitcoin\blocks\blk00003.dat'

# Read the block data
block_data, block_timestamp = read_block(block_file)

# Build the UTXO map for sender address resolution
utxo_map = build_utxo_map(block_data)

# Parse the block transactions
transactions = parse_block(block_data, block_timestamp, utxo_map)

# Print the transaction details
for tx in transactions:
    print(f"Date (UTC): {tx['Date']}")
    print(f"Amount: {tx['Amount']} BTC")
    print(f"Sender Address: {tx['Sender Address']}")
    print(f"Receiver Address: {tx['Receiver Address']}")
    print(f"TXID: {tx['TXID']}")
    print('---')
