#!/usr/bin/env python3


def memfrob(data: bytes) -> bytes:
    tmp = 0xFF
    result = []

    for i, byte in enumerate(data):
        byte = (byte ^ tmp) & 0xFF

        byte = (byte ^ (i)) & 0xFF
        byte = (byte + (i*i)) & 0xFF
        byte = (byte ^ (i*i*i)) & 0xFF
        byte = (byte + (i*i*i*i)) & 0xFF

        result.append(byte)

        tmp = (tmp + byte) & 0xFF

    return bytes(result)


def unmemfrob(data: bytes) -> bytes:
    tmp = 0xFF
    tmp = (tmp + sum(data)) & 0xFF

    unprotected = []

    for i, byte in reversed(list(enumerate(data))):
        tmp = (tmp - byte) & 0xFF

        byte = (byte - (i*i*i*i)) & 0xFF
        byte = (byte ^ (i*i*i)) & 0xFF
        byte = (byte - (i*i)) & 0xFF
        byte = (byte ^ (i)) & 0xFF

        byte = (byte ^ tmp) & 0xFF

        unprotected.append(byte)

    return bytes(unprotected[::-1])


def insert_array(
        source_path: str,
        content_path: str,
        output_path: str,
) -> None:
    with open(source_path, 'r') as file:
        source = file.read()

    with open(content_path, 'rb') as file:
        content = file.read()

    chunk_size = 20_000
    constants = []

    for i in range(0, len(content), chunk_size):
        chunk = content[i : i+chunk_size]
        chunk = unmemfrob(chunk)

        constant = ''.join(
            '\\' + oct(byte)[2:].zfill(3) for byte in chunk
        )
        constants.append(constant)

    variables = '\n'.join(
        f'private static final String LibraryPart{i} = "{constant}";' for i, constant in enumerate(constants)
    )
    writes = '\n'.join(
        f'bufferedStream.write(decryptData(LibraryPart{i}.getBytes(StandardCharsets.ISO_8859_1)));'
        for i in range(len(constants))
    )

    source = source.replace('// VARIABLES', variables)
    source = source.replace('// WRITES', writes)

    with open(output_path, 'w') as file:
        file.write(source)

    return


def main() -> None:
    insert_array(
        source_path = './Dolly.template.java',
        content_path = './libchecker.so',
        output_path = './Dolly.java',
    )

    return


if __name__ == '__main__':
    main()
