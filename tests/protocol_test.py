import ctypes
import pathlib
import struct
import subprocess
import tempfile
import zlib

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    library = pathlib.Path(directory) / 'protocol.so'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', str(root / 'src/dualsense.c'), '-o', str(library)], check=True)
    lib = ctypes.CDLL(str(library))
    decode = lib.dualsense_decode_bluetooth
    decode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    state = ctypes.create_string_buffer(256)
    vectors = [(9,4,0x8000),(9,5,0x4000),(9,6,0x2000),(9,7,0x1000),(10,0,0x400),(10,1,0x800),(10,2,0x100),(10,3,0x200),(10,4,1),(10,5,8),(10,6,2),(10,7,4),(11,0,0x10000),(11,1,0x100000)]
    for offset, bit, expected in vectors:
        packet = bytearray(78)
        packet[0], packet[9] = 0x31, 8
        packet[offset] |= 1 << bit
        packet[74:] = zlib.crc32(b'\xa1' + packet[:74]).to_bytes(4, 'little')
        assert decode(bytes(packet), 78, state) == 0
        assert struct.unpack_from('<I', state.raw)[0] == expected
    for direction, expected in enumerate([16,48,32,96,64,192,128,144,0]):
        packet = bytearray(78)
        packet[0], packet[9] = 0x31, direction
        packet[74:] = zlib.crc32(b'\xa1' + packet[:74]).to_bytes(4, 'little')
        assert decode(bytes(packet), 78, state) == 0
        assert struct.unpack_from('<I', state.raw)[0] == expected
    saved = state.raw
    packet[5] ^= 1
    assert decode(bytes(packet), 78, state) == -2
    assert state.raw == saved
    assert decode(bytes(packet), 77, state) == -1
    assert decode(bytes([1,128,128,128,128,8,0,0,0,0]), 10, state) == 0
    assert state.raw[11] == 0
    output = ctypes.create_string_buffer(78)
    color = ctypes.create_string_buffer(bytes([20,30,40]))
    lib.dualsense_output_bluetooth(output, 7, 110, 90, color, 0)
    packet = output.raw
    assert packet[:7] == bytes([49,112,16,3,20,90,110])
    assert packet[47:50] == bytes([20,30,40])
    assert int.from_bytes(packet[74:], 'little') == zlib.crc32(b'\xa2' + packet[:74])
    calibration = bytearray(41)
    calibration[0] = 5
    for axis in range(3):
        struct.pack_into('<hh', calibration, 7 + axis * 4, 16000, -16000)
        struct.pack_into('<hh', calibration, 23 + axis * 4, 8192, -8192)
    struct.pack_into('<hh', calibration, 19, 1000, 1000)
    calibration[37:] = zlib.crc32(b'\xa3' + calibration[:37]).to_bytes(4, 'little')
    values = (ctypes.c_float * 9)()
    assert lib.dualsense_calibration_bluetooth(bytes(calibration), 41, values) == 0
    assert abs(values[3] - 1 / 8192) < 1e-9
    calibration[3] ^= 1
    assert lib.dualsense_calibration_bluetooth(bytes(calibration), 41, values) == -2
print('Protocol, button mapping, output CRC and factory calibration checks passed')
