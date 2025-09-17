import random
def generate_sbox_2d():
    """ #COMMENT: SOLE PURPOSE IS TO PROVIDE A COPY OF SBOX WHEN NEEDED/FUNCTION IS CALLED.
    Generate the AES S-box as a 16x16 2D array.
    Row index = high nibble (upper 4 bits)
    Column index = low nibble (lower 4 bits)
    """
    # AES S-box arranged as 16x16 matrix
    sbox = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ]
    return sbox


def print_sbox():
    """
    Print the S-box in a nicely formatted 16x16 table with row/column headers.
    """
    sbox = generate_sbox_2d()

    print("AES S-box (SubBytes lookup table):")
    print("     ", end="")

    # Print column headers (0-F)
    for col in range(16):
        print(f" {col:X} ", end="")
    print()

    # Print separator line
    print("   +" + "-" * 48)

    # Print each row with row header
    for row in range(16):
        print(f" {row:X} | ", end="")
        for col in range(16):
            print(f"{sbox[row][col]:02x} ", end="")
        print()
    print()


def sbox_lookup(byte_value):
    """
    Perform S-box lookup using row/column indexing.

    Args:
        byte_value: Input byte (0-255)

    Returns:
        Substituted byte value and lookup details
    """
    sbox = generate_sbox_2d() #COMMENT: GRABS SBOX from SBOX function. ALWAYS THE SAME

    # Extract high and low nibbles
    high_nibble = (byte_value >> 4) & 0x0F  # Upper 4 bits (row)
    low_nibble = byte_value & 0x0F  # Lower 4 bits (column)

    # Lookup in S-box
    substituted_value = sbox[high_nibble][low_nibble]

    return substituted_value, high_nibble, low_nibble


def subbytes(state):
    """
    Apply the SubBytes transformation to the AES state using 2D S-box lookup.

    Args:
        state: 4x4 matrix (list of lists) representing the AES state

    Returns:
        4x4 matrix with SubBytes transformation applied
    """
    sbox = generate_sbox_2d() #COMMENT: Grabs a copy of sbox

    # Create a copy of the state to avoid modifying the original
    new_state = [[0 for _ in range(4)] for _ in range(4)] #COMMENT: Makes a 4x4 matrix

    # Apply S-box substitution to each byte
    print("SubBytes transformations:")
    for row in range(4):
        for col in range(4):  #Goes row by row
            byte_val = state[row][col]

            # Extract nibbles for 2D lookup
            high_nibble = (byte_val >> 4) & 0x0F  # Row index COMMENT: GETS YOU bit 0-15
            low_nibble = byte_val & 0x0F  # Column index COMMENT: gets you bit 0-15

            # Perform 2D S-box lookup
            substituted_val = sbox[high_nibble][low_nibble] # COMMENT: Gets you a value from sbox
            new_state[row][col] = substituted_val

            # Show the lookup process
            print(
                f"  State[{row}][{col}]: 0x{byte_val:02x} -> S-box[{high_nibble:X}][{low_nibble:X}] = 0x{substituted_val:02x}")

    return new_state #COMMENT: Returns the array of subbytes from plaintext


def shiftRows(matrix):
    # Create a copy of the state to avoid modifying the original
    new_state = [[0 for _ in range(4)] for _ in range(4)]

    # shift each row to the left starting with 2nd row and incrementing
    # shift for each additional row
    for c in range(0, len(matrix[0])):
        new_state[0][c] = matrix[0][c] # COMMENT: Just copies row 0 since it shifts 0 times i.e no change
    for r in range(1, len(matrix)): #COMMENT: Start at row 1 since row 0 was already copied unchanged
        for c in range(0, len(matrix[0])):
            c2 = (r + c) % 4  #COMMENT: Prints by column, moves onto next row. R+C row =shift, col = which column we are moving.
            new_state[r][c] = matrix[r][c2]
    return new_state


def getBinary(letter):
    binary = ''
    print(letter)
    val = bin(ord(letter))
    val = val.removeprefix('0b')
    for i in range(8 - len(val)):
        val = '0' + val
    return val


def addRoundKey(roundkey, matrix):
    # Create a copy of the state to avoid modifying the original
    new_state = [[0 for _ in range(4)] for _ in range(4)]

    for r in range(len(matrix)):
        for c in range(len(matrix)):
            # convert to binary for data and key
            # matrix is in decimal format so
            # convert to binary and remove "0b" prefix
            # roundkey are characters
            # convert to decimal then binary
            b1 = bin(matrix[r][c])[2:].zfill(8) #COMMENT: (2: Slices of first 2 chars) (zfill(8)) pads left with 0's to make 8 chars long
            b2 = bin(ord(roundkey[r][c])).removeprefix('0b').zfill(8) #turns alphabet letter to ascii, then turns it into binary,
                                                                      #removes 0b and fills left with 0's
            # xor data with key
            new_state[r][c] = xor(b1, b2) #DOES XOR on the roundkey and the state
            # convert binary back to integer
            new_state[r][c] = int(new_state[r][c], 2) #turns bits into integer and stores it.

    return new_state


def xor(b1, b2):
    val = ''
    for i in range(len(b1)): #COMMENT: IF BITS ARE SAME = 0, IF BITS ARE OPPOPSITE = 1
        if b1[i] == '0' and b2[i] == '0':
            val = val + '0'
        elif b1[i] == '0' and b2[i] == '1':
            val = val + '1'
        elif b1[i] == '1' and b2[i] == '0':
            val = val + '1'
        else:
            val = val + '0'
    return val

def generate_roundkey():
    new_key = [["@" for _ in range(4)] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_letter = random.randint(97,122)
            new_key[r][c] = chr(new_letter)
    return new_key


def print_state(state, title="State"):
    """
    Print the state matrix in hexadecimal format.
    """
    print(f"\n{title}:")
    for row in state:
        print(" ".join(f"{byte:02x}" for byte in row)) #COMMENT: converts it to hexidecimal
    print()


# Example usage and testing
def main():
    print("AES SubBytes Step with 2D S-box Lookup")
    print("=" * 50)

    # Display the S-box table
    # print_sbox()

    plaintext = input("Enter plaintext: ")

    # Pad or truncate to exactly 16 characters
    if len(plaintext) < 16:                   #COMMENT: Checks if len is 16, if not it pads it with null characters
        plaintext = plaintext.ljust(16, '\0')  # Pad with null characters
    elif len(plaintext) > 16:
        plaintext = plaintext[:16]  # Truncate to 16 characters
        # #COMMENT FIX to allow more than 16 bytes to be encrypted

    # Convert plaintext to 4x4 state matrix
    # AES state is filled column by column
    test_state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(16):     #COMMENT: Fills it column by column
        row = i % 4
        col = i // 4
        test_state[row][col] = ord(plaintext[i])

    print(f"Input plaintext: '{plaintext}'")     #COMMENT: Displays the chars, ASCII value of chars & hex
    print("Characters: " + " ".join(f'{c:>3}' for c in plaintext))
    print("Bytes     : " + " ".join(f'{ord(c):3}' for c in plaintext))
    print("Hex       : " + " ".join(f'{ord(c):3x}' for c in plaintext))

    print_state(test_state, "Original State") #COMMENT: Pass in our array of our plain text prints it in HEX

    # Apply SubBytes with detailed lookup information
    after_subbytes = subbytes(test_state) #COMMENT: pass in our array of plaintext,
    print_state(after_subbytes, "After SubBytes")

    # Apply ShiftRows
    after_shiftrows = shiftRows(after_subbytes) #COMMNENT: Shifts rows by row number.
    print_state(after_shiftrows, "After Shift Rows")

    # After RoundKey

    roundkey = generate_roundkey() #COMMENT: Make round key not hardcoded
    print(roundkey)
    after_roundkeys = addRoundKey(roundkey, after_shiftrows)
    print_state(after_roundkeys, "After Round Keys")


main()