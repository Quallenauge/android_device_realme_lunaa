#!/usr/bin/env -S PYTHONPATH=../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: 2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

import struct

from extract_utils.fixups_blob import (
    BlobFixupCtx,
    File,
    blob_fixup,
    blob_fixups_user_type,
)
from extract_utils.fixups_lib import (
    lib_fixups,
)
from extract_utils.main import (
    ExtractUtils,
    ExtractUtilsModule,
)
from extract_utils.tools import (
    llvm_objdump_path,
)
from extract_utils.utils import (
    run_cmd,
)

namespace_imports = [
    'hardware/oplus',
    'vendor/oneplus/sm8350-common',
    'vendor/qcom/opensource/display',
]


def blob_fixup_nop_call(
    ctx: BlobFixupCtx,
    file: File,
    file_path: str,
    call_instruction: str,
    disassemble_symbol: str,
    symbol: str,
    *args,
    **kwargs,
):
    for line in run_cmd(
        [
            llvm_objdump_path,
            f'--disassemble-symbols={disassemble_symbol}',
            file_path,
        ]
    ).splitlines():
        line = line.split(maxsplit=3)

        if len(line) != 4:
            continue

        offset, _, instruction, args = line

        if instruction != call_instruction:
            continue

        if not args.endswith(f' <{symbol}>'):
            continue

        with open(file_path, 'rb+') as f:
            f.seek(int(offset[:-1], 16))
            f.write(b'\x1f\x20\x03\xd5')  # AArch64 NOP

        break


def blob_fixup_chi_debug_data_buffer(
    ctx: BlobFixupCtx,
    file: File,
    file_path: str,
    *args,
    **kwargs,
):
    # Feature2Wrapper::ProcessResult copies the DebugDataAll blob of every result into a buffer
    # that it allocates once, with the size of the first blob it sees. A later, larger blob
    # overflows the heap and at times kills the provider shortly after a session starts.
    # Allocate 4 MiB instead of the first size (the largest blob seen is 2.3 MB):
    #   ldr x27, [x23]  ->  mov x27, #0x400000
    #   mov x0, x27
    #   bl malloc
    old = bytes.fromhex('fb0240f9e0031baa')
    new = bytes.fromhex('1b08a0d2e0031baa')

    with open(file_path, 'rb+') as f:
        data = f.read()
        assert data.count(old) == 1, 'debug data allocation not found'
        f.seek(data.index(old))
        f.write(new)


def blob_fixup_tuning_full_res_tone_mapping(
    ctx: BlobFixupCtx,
    file: File,
    file_path: str,
    *args,
    **kwargs,
):
    # Chromatix binary (Parameter Parser V3): section table at 0xa0; section 0 holds the symbols
    # (56 bytes: id, name[40], mode id, offset into section 1, size), section 2 the modes
    # (20 bytes: id, type | subtype << 16, slot, parent, -1; type 1 is the sensor mode).
    #
    # Sensor mode 0, the full 64 MP readout, has no tone mapping of its own and falls back to
    # the default, which leaves the shadows of its pictures darker than those of the 16 MP
    # modes. Give it the entries of a 16 MP snapshot variant that is not used here
    # (sensor 3, usecase 1, feature1 22, feature2 25, scene 21) and raise their shadow lift.
    spare_path = [(1, 3), (2, 1), (3, 22), (4, 25), (5, 21)]
    target_path = [(1, 0)]
    dark_boost_offset = 1.0  # default entry: 0.4 in bright light, spare entry: 0
    tmc_region_size = 300    # floats; the two dark boost offsets are words 9 and 10

    with open(file_path, 'rb+') as f:
        data = bytearray(f.read())

        sections = {}
        for i in range(struct.unpack_from('<I', data, 0xA4)[0]):
            section, offset, size = struct.unpack_from('<III', data, 0xA8 + 12 * i)
            sections[section] = (offset, size)

        modes = {}
        for i in range(sections[2][1] // 20):
            mode, kind, slot, parent, _ = struct.unpack_from('<IIIII', data, sections[2][0] + 20 * i)
            modes[mode] = (kind & 0xFFFF, kind >> 16, slot, parent)

        def mode_path(mode):
            path = []
            while modes[mode][0] != 0:
                kind, subtype, _, parent = modes[mode]
                if not path or path[0][0] != kind:
                    path.insert(0, (kind, subtype))
                mode = parent
            return path

        symbols = {}
        for i in range(sections[0][1] // 56):
            offset = sections[0][0] + 56 * i
            symbol = struct.unpack_from('<I', data, offset)[0]
            name = data[offset + 4 : offset + 44].split(b'\0')[0].decode()
            mode, data_offset, size = struct.unpack_from('<III', data, offset + 44)
            symbols[symbol] = (name, mode, sections[1][0] + data_offset, size, offset)

        def children(symbol, name):
            _, _, offset, size, _ = symbols[symbol]
            for word in range(0, size - 7, 4):
                count, child = struct.unpack_from('<II', data, offset + word)
                if 0 < count < 1000 and child in symbols and symbols[child][0] == name:
                    yield child

        moved = 0
        for symbol, (name, mode, _, _, entry) in symbols.items():
            if name not in ('tmc13_sw', 'ltm13_ipe') or mode == 0xFFFFFFFF:
                continue
            if mode_path(mode) != spare_path:
                continue

            slot = modes[mode][2]
            (target,) = [m for m in modes if modes[m][2] == slot and mode_path(m) == target_path]
            struct.pack_into('<I', data, entry + 44, target)
            moved += 1

            if name != 'tmc13_sw':
                continue
            for drc in children(symbol, 'mod_tmc13_drc_gain_data'):
                for hdr in children(drc, 'mod_tmc13_hdr_aec_data'):
                    for aec in children(hdr, 'mod_tmc13_aec_data'):
                        _, _, offset, size, _ = symbols[aec]
                        for region in range(offset, offset + size, tmc_region_size):
                            struct.pack_into('<ff', data, region + 36, dark_boost_offset, dark_boost_offset)

        assert moved == 2, 'tone mapping entries not found'
        f.seek(0)
        f.write(data)


blob_fixups: blob_fixups_user_type = {
    'odm/etc/camera/CameraHWConfiguration.config': blob_fixup()
        .regex_replace('SystemCamera =  0;  0;  1;  1;  1', 'SystemCamera =  0;  0;  0;  0;  1'),
    ('odm/lib/liblvimfs_wrapper.so', 'odm/lib64/libCOppLceTonemapAPI.so', 'odm/lib64/libaps_frame_registration.so'): blob_fixup()
        .replace_needed('libstdc++.so', 'libstdc++_vendor.so'),
    ('odm/lib64/libarcsoft_high_dynamic_range_v4.so', 'odm/lib64/libarcsoft_portrait_super_night_raw.so'): blob_fixup()
        .clear_symbol_version('remote_handle_close')
        .clear_symbol_version('remote_handle_invoke')
        .clear_symbol_version('remote_handle_open')
        .clear_symbol_version('remote_handle64_close')
        .clear_symbol_version('remote_handle64_invoke')
        .clear_symbol_version('remote_handle64_open')
        .clear_symbol_version('remote_register_buf_attr')
        .clear_symbol_version('remote_register_buf')
        .clear_symbol_version('rpcmem_alloc')
        .clear_symbol_version('rpcmem_free')
        .clear_symbol_version('rpcmem_to_fd'),
    'odm/lib64/camera/com.qti.tuned.qtech_ov64b.bin': blob_fixup()
        .call(blob_fixup_tuning_full_res_tone_mapping),
    'odm/lib64/libAlgoProcess.so': blob_fixup()
        .replace_needed('android.hardware.graphics.common-V1-ndk_platform.so', 'android.hardware.graphics.common-V7-ndk.so'),
    'odm/lib64/libOGLManager.so': blob_fixup()
        .clear_symbol_version('AHardwareBuffer_allocate')
        .clear_symbol_version('AHardwareBuffer_describe')
        .clear_symbol_version('AHardwareBuffer_lock')
        .clear_symbol_version('AHardwareBuffer_release')
        .clear_symbol_version('AHardwareBuffer_unlock'),
    'vendor/etc/libnfc-hal-st.conf':  blob_fixup()
        .regex_replace('NFC_DEBUG_ENABLED=1', 'NFC_DEBUG_ENABLED=0')
        .regex_replace('STNFC_FW_PATH_STORAGE="/data/vendor/nfc/"', 'STNFC_FW_PATH_STORAGE="/vendor/firmware/"')
        .regex_replace('STNFC_FW_CONF_NAME="/data/vendor/nfc/libnfc-st21h_conf.txt"', 'STNFC_FW_CONF_NAME="libnfc-st21h_conf.txt"'),
    'vendor/etc/libnfc-nci.conf': blob_fixup()
        .regex_replace('NFC_DEBUG_ENABLED=1', 'NFC_DEBUG_ENABLED=0'),
    'vendor/lib64/hw/com.qti.chi.override.so': blob_fixup()
        .call(blob_fixup_chi_debug_data_buffer),
}  # fmt: skip

module = ExtractUtilsModule(
    'lunaa',
    'realme',
    namespace_imports=namespace_imports,
    blob_fixups=blob_fixups,
    lib_fixups=lib_fixups,
    add_firmware_proprietary_file=False,
)

if __name__ == '__main__':
    utils = ExtractUtils.device_with_common(
        module, '../oneplus/sm8350-common', module.vendor
    )
    utils.run()
