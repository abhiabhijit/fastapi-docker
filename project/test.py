import base64
import binascii
import json
import re

import msgpack
import requests

base_url = "https://ciphersprint.pulley.com/"
email = "abhijitastlar@gmail.com"


def decode_ascii_array(ascii_array):
    """Decodes a JSON array of ASCII values to a string."""
    return "".join(chr(c) for c in ascii_array)


def swap_pairs(encrypted_str):
    """Swaps every pair of characters in the encrypted string."""
    decrypted = []
    for i in range(0, len(encrypted_str), 2):
        if i + 1 < len(encrypted_str):
            decrypted.append(encrypted_str[i + 1])
            decrypted.append(encrypted_str[i])
        else:
            decrypted.append(encrypted_str[i])
    return "".join(decrypted)


def circular_rotate_right(s, n):
    """Circularly rotates a string right by n characters."""
    n = n % len(s)  # Handle rotation greater than length
    return s[-n:] + s[:-n]


def xor_decrypt(encrypted_bytes, key):
    """Decrypts bytes encrypted with XOR using the provided key."""
    key_bytes = key.encode()
    decrypted_bytes = bytearray(
        b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_bytes)
    )
    return decrypted_bytes


def parse_rotation_amount(encryption_method):
    """Extracts the rotation amount from the encryption method description."""
    match = re.search(r"left by (\d+)", encryption_method)
    if match:
        return int(match.group(1))
    else:
        raise ValueError(
            f"Rotation amount not found in encryption method: {encryption_method}"
        )


def unscramble(scrambled_str, positions):
    """Unscrambles the string based on the given positions."""
    unscrambled = [""] * len(scrambled_str)
    for i, pos in enumerate(positions):
        unscrambled[pos] = scrambled_str[i]
    return "".join(unscrambled)


def fetch_next_challenge(base_url, path, encryption_method):
    """Fetches the next challenge based on the encryption method."""
    if encryption_method == "nothing":
        path = path
    elif encryption_method == "converted to a JSON array of ASCII values":
        ascii_array = json.loads(path.replace("task_", ""))
        path = decode_ascii_array(ascii_array)
        path = "task_" + path
    elif encryption_method == "swapped every pair of characters":
        encrypted_str = path.replace("task_", "")
        path = swap_pairs(encrypted_str)
        path = "task_" + path
    elif "circularly rotated left by" in encryption_method:
        encrypted_str = path.replace("task_", "")
        rotation_amount = parse_rotation_amount(encryption_method)
        path = circular_rotate_right(encrypted_str, rotation_amount)
        path = "task_" + path
        print(f"Rotated path: {path}")  # Debug: Print the rotated path
    elif "hex decoded, encrypted with XOR" in encryption_method:
        encrypted_str = path.replace("task_", "")
        hex_decoded_bytes = binascii.unhexlify(encrypted_str)
        key = "secret"
        decrypted_bytes = xor_decrypt(hex_decoded_bytes, key)
        # hex encode
        path = decrypted_bytes.hex()
        path = "task_" + path
        print(f"Decrypted path: {path}")  # Debug: Print the decrypted path
    elif "scrambled!" in encryption_method:
        encrypted_str = path.replace("task_", "")
        base64_positions = encryption_method.split(": ")[1]
        decoded_positions = base64.b64decode(base64_positions)
        positions = msgpack.unpackb(decoded_positions)
        path = unscramble(encrypted_str, positions)
        path = "task_" + path
        print(f"Unscrambled path: {path}")  # Debug: Print the unscrambled path
    elif encryption_method == "hashed with sha256, good luck":
        print("Congratulations! You've reached the final level.")
        print(
            "This level is designed to be unsolvable as SHA256 is a one-way hash function."
        )
        return {
            "message": "You've completed all solvable levels!",
            "level": 6,
            "is_final": True,
        }
    else:
        raise ValueError(f"Unknown encryption method: {encryption_method}")

    print(f"Fetching URL: {base_url}{path}")  # Debug: Print the URL being fetched
    url = f"{base_url}{path}"
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to fetch the challenge. Status code: {response.status_code}"
        }


def main(base_url, email):
    # Start with the initial email request
    response = requests.get(f"{base_url}{email}")
    response_data = response.json()

    while True:
        encrypted_path = response_data.get("encrypted_path")
        encryption_method = response_data.get("encryption_method")

        if not encrypted_path or not encryption_method:
            break

        response_data = fetch_next_challenge(
            base_url, encrypted_path, encryption_method
        )
        print(response_data)

        if "error" in response_data:
            break


if __name__ == "__main__":
    main(base_url, email)
