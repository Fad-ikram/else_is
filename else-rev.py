
""" ikram's solution """
import struct
BINARY_PATH = "/home/kali/Desktop/else_if"

VM_PROGRAM_OFFSET = 0x2140

MASK32 = 0xFFFFFFFF

STRING_LENGTH = 44
TARGET_SCORE = 366

PRINTABLE_CHARS = list(range(32, 127))


OPCODE_NAMES = {
    0x00: "EXIT",
    0x01: "PUSHI",
    0x02: "PUSHIN",
    0x03: "PUSHLEN",
    0x04: "PUSHACC",
    0x10: "ADD",
    0x11: "SUB",
    0x12: "XOR",
    0x20: "EQ",
    0x21: "LT",
    0x22: "LE",
    0x23: "GT",
    0x24: "GE",
    0x30: "ADDIF",
    0x31: "CHKACC",
    0x40: "DECRYPT",
    0x41: "CALL",
    0x42: "PRINT",
    0xFF: "HALT"
}


OPERAND_SIZE = {
    0x01: 4,
    0x02: 2,
    0x30: 2,
    0x31: 4
}


def read_binary(path):
    with open(path, "rb") as file:
        binary = file.read()

    return binary


def get_outer_program(binary):
    return binary[VM_PROGRAM_OFFSET:]


def parse_program(raw):
    if raw[:4] != b"NVM1":
        raise ValueError("NVM1 header not found!")

    kb = raw[5]

    code_len = struct.unpack_from("<I", raw, 8)[0]
    data_len = struct.unpack_from("<I", raw, 12)[0]
    aux_len = struct.unpack_from("<I", raw, 16)[0]

    header_size = 20

    code_start = header_size
    code_end = code_start + code_len

    data_start = code_end
    data_end = data_start + data_len

    aux_start = data_end
    aux_end = aux_start + aux_len

    if aux_end > len(raw):
        raise ValueError("Invalid NVM1 program lengths!")

    code = raw[code_start:code_end]
    data = raw[data_start:data_end]
    aux = raw[aux_start:aux_end]

    return kb, code, data, aux


def decrypt_blob(kb, ciphertext, key):
    n = len(ciphertext)

    e = (0x1D * kb + key + 13 * (n - 1)) & MASK32

    plaintext = bytearray(n)

    for i in range(n):
        src_index = n - 1 - i

        plaintext[i] = ciphertext[src_index] ^ (e & 0xFF)

        e = (e - 13) & MASK32

    return bytes(plaintext)


def disassemble(code):
    instructions = []

    pc = 0

    while pc < len(code):
        op = code[pc]

        name = OPCODE_NAMES.get(op, "UNKNOWN")

        operand_size = OPERAND_SIZE.get(op, 0)

        operand = None

        if pc + 1 + operand_size > len(code):
            raise ValueError("Incomplete instruction!")

        if operand_size > 0:
            operand = int.from_bytes(
                code[pc + 1:pc + 1 + operand_size],
                "little"
            )

        instructions.append((name, operand))

        pc = pc + 1 + operand_size

    return instructions


def looks_like_a_wrapper(instructions):
    if len(instructions) != 4:
        return False

    if instructions[0][0] != "PUSHI":
        return False

    if instructions[1][0] != "DECRYPT":
        return False

    if instructions[2][0] != "CALL":
        return False

    if instructions[3][0] != "HALT":
        return False

    return True


def peel_all_wrapper_layers(program):
    current = program
    layer_count = 0

    while True:
        kb, code, data, aux = parse_program(current)

        instructions = disassemble(code)

        if not looks_like_a_wrapper(instructions):
            print("Reached the real program!")
            print("Layers decrypted:", layer_count)

            return current

        key = instructions[0][1]

        current = decrypt_blob(kb, data, key)

        layer_count = layer_count + 1

        print("Decrypted layer:", layer_count)


def split_into_statements(instructions):
    statements = []

    current_statement = []

    for name, operand in instructions:

        if name == "CHKACC":
            break

        if name == "PRINT":
            break

        if name == "HALT":
            break

        current_statement.append((name, operand))

        if name == "ADDIF":
            statements.append(current_statement)
            current_statement = []

    return statements


def evaluate_statement(statement, candidate_input, input_length):
    stack = []

    for name, operand in statement:

        if name == "PUSHI":
            stack.append(operand)

        elif name == "PUSHIN":
            if operand >= len(candidate_input):
                return 0

            stack.append(candidate_input[operand])

        elif name == "PUSHLEN":
            stack.append(input_length)

        elif name == "ADDIF":
            condition = stack.pop()

            if condition:
                return operand

            return 0

        elif name == "ADD":
            b = stack.pop()
            a = stack.pop()

            stack.append((a + b) & MASK32)

        elif name == "SUB":
            b = stack.pop()
            a = stack.pop()

            stack.append((a - b) & MASK32)

        elif name == "XOR":
            b = stack.pop()
            a = stack.pop()

            stack.append(a ^ b)

        elif name == "EQ":
            b = stack.pop()
            a = stack.pop()

            stack.append(1 if a == b else 0)

        elif name == "LT":
            b = stack.pop()
            a = stack.pop()

            stack.append(1 if a < b else 0)

        elif name == "LE":
            b = stack.pop()
            a = stack.pop()

            stack.append(1 if a <= b else 0)

        elif name == "GT":
            b = stack.pop()
            a = stack.pop()

            stack.append(1 if a > b else 0)

        elif name == "GE":
            b = stack.pop()
            a = stack.pop()

            stack.append(1 if a >= b else 0)

        else:
            raise ValueError("Unsupported instruction: " + name)

    return 0


def get_positions(statement):
    positions = []

    for name, operand in statement:
        if name == "PUSHIN":
            positions.append(operand)

    return positions


def find_statements_for_position(statements, position):
    relevant = []

    for statement in statements:
        positions = get_positions(statement)

        if positions and max(positions) == position:
            relevant.append(statement)

    return relevant


def solve(binary_path, string_length, target_score):
    binary = read_binary(binary_path)

    outer_program = get_outer_program(binary)

    real_program = peel_all_wrapper_layers(outer_program)

    kb, code, data_blob, aux = parse_program(real_program)

    instructions = disassemble(code)

    statements = split_into_statements(instructions)

    print("Scoring statements found:", len(statements))

    length_bonus = 0

    character_statements = []

    for statement in statements:

        positions = get_positions(statement)

        if len(positions) == 0:
            length_bonus += evaluate_statement(
                statement,
                [0] * string_length,
                string_length
            )

        else:
            character_statements.append(statement)

    remaining_target = target_score - length_bonus

    print("Length bonus:", length_bonus)
    print("Remaining target:", remaining_target)

    max_distance = 0

    for statement in character_statements:
        positions = get_positions(statement)

        distance = max(positions) - min(positions)

        if distance > max_distance:
            max_distance = distance

    states = {
        ("", 0): ""
    }

    for position in range(string_length):

        relevant_statements = find_statements_for_position(
            character_statements,
            position
        )

        new_states = {}

        for (recent_chars, score), built_string in states.items():

            for candidate_char in PRINTABLE_CHARS:

                candidate_input = [0] * string_length

                start_position = position - len(recent_chars)

                for i in range(len(recent_chars)):
                    candidate_input[start_position + i] = ord(
                        recent_chars[i]
                    )

                candidate_input[position] = candidate_char

                extra_points = 0

                for statement in relevant_statements:
                    extra_points += evaluate_statement(
                        statement,
                        candidate_input,
                        string_length
                    )

                new_score = score + extra_points

                if new_score <= remaining_target:

                    new_string = built_string + chr(candidate_char)

                    new_recent_chars = recent_chars + chr(candidate_char)

                    if max_distance > 0:
                        new_recent_chars = new_recent_chars[-max_distance:]
                    else:
                        new_recent_chars = ""

                    state_key = (new_recent_chars, new_score)

                    if state_key not in new_states:
                        new_states[state_key] = new_string

        states = new_states

        print(
            "Position",
            position + 1,
            "- Possible states:",
            len(states)
        )

    answers = []

    for (recent_chars, score), built_string in states.items():

        if score == remaining_target:
            answers.append(built_string)

    return answers

if __name__ == "__main__":

    results = solve(
        BINARY_PATH,
        STRING_LENGTH,
        TARGET_SCORE
    )

    print("\nPossible answers:")

    if len(results) == 0:
        print("No answer found.")
    else:
        for answer in results:
            print(answer)
