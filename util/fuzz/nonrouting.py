"""
Utilities for fuzzing non-routing configuration. This is the counterpart to interconnect.py
"""

import sys
import threading
import tiles
import pytrellis


def check_enum_setting(config, name, values, get_ncl_substs, empty_bitfile=None):
    """
    Verify that building each value of an enum setting produces exactly the bit pattern
    recorded in the database.  Runs a full sweep (every value in `values`).

    Checks in both directions:
    1. Every bit the database expects for a value is present in the bitstream.
    2. No bits change between values that the database doesn't account for
       (catches extra bits Diamond sets that prjtrellis never recorded).

    NEVER exits.  Returns a list of error strings (empty = all match).
    The caller is responsible for accumulating errors and exiting at the end.
    """
    prefix = "chk{}_".format(threading.get_ident())
    tile_dbs = {tile: pytrellis.get_tile_bitdata(
        pytrellis.TileLocator(config.family, config.device, tiles.type_from_fullname(tile)))
        for tile in config.tiles}

    errors = []

    # Build all bitstreams first, keyed by value
    chips = {}
    for val in values:
        print("****** Checking {} = {} ******".format(name, val))
        bit_bitf = config.build_design(config.ncl, get_ncl_substs(val), prefix)
        chips[val] = pytrellis.Bitstream.read_bit(bit_bitf).deserialise_chip()

    for tile in config.tiles:
        tdb = tile_dbs[tile]
        tile_type = tiles.type_from_fullname(tile)

        try:
            esb = tdb.get_data_for_enum(name)
        except Exception:
            errors.append("MISSING_IN_DB: setting '{}' not found in database for tile {} ({})".format(
                name, tile, tile_type))
            continue

        # Collect the set of (frame, bit) positions the database knows about for this setting
        known_bits = set()
        for val, bg in esb.options.items():
            for cb in bg.bits:
                known_bits.add((cb.frame, cb.bit))

        for val in values:
            if val not in esb.options:
                errors.append("MISSING_VALUE: value '{}' for setting '{}' not in database for tile {}".format(
                    val, name, tile))
                continue

            expected_bg = esb.options[val]
            cram = chips[val].tiles[tile].cram

            # Check 1: every bit the db expects is correct in the actual bitstream
            for cb in expected_bg.bits:
                actual = cram.bit(cb.frame, cb.bit)
                want = 0 if cb.inv else 1
                if actual != want:
                    errors.append(
                        "BIT_MISMATCH: {} value={} tile={} F{}B{}: db_expects={} diamond_got={}".format(
                            name, val, tile, cb.frame, cb.bit, want, actual))

            # Check 2: no bit outside the known set changes between this value and any other
            # (detects bits Diamond sets that the database never recorded)
            for other_val, other_chip in chips.items():
                if other_val == val:
                    continue
                other_cram = other_chip.tiles[tile].cram
                diff = cram - other_cram
                for bit in diff:
                    if (bit.frame, bit.bit) not in known_bits:
                        errors.append(
                            "EXTRA_BIT: {} value={} vs value={} tile={} F{}B{}: "
                            "bit differs but not in database for this setting".format(
                                name, val, other_val, tile, bit.frame, bit.bit))

    if errors:
        print("MISMATCH: {} — {} discrepancy(s)".format(name, len(errors)))
        for e in errors:
            print("  " + e)
    else:
        print("OK: {} — all {} values match database (both directions)".format(name, len(values)))

    return errors


def check_word_setting(config, name, length, get_ncl_substs, empty_bitfile=None):
    """
    Verify that each bit position of a word setting produces the bit pattern recorded
    in the database when set to 1 (full sweep: one build per bit position).

    Checks in both directions:
    1. Every bit the database expects for each bit position is present.
    2. No bits change that the database doesn't account for
       (catches extra bits Diamond sets that prjtrellis never recorded).

    NEVER exits.  Returns a list of error strings (empty = all match).
    The caller is responsible for accumulating errors and exiting at the end.
    """
    prefix = "chkw{}_".format(threading.get_ident())
    tile_dbs = {tile: pytrellis.get_tile_bitdata(
        pytrellis.TileLocator(config.family, config.device, tiles.type_from_fullname(tile)))
        for tile in config.tiles}

    baseline_bitf = config.build_design(config.ncl, get_ncl_substs([False for _ in range(length)]), prefix)
    baseline_chip = pytrellis.Bitstream.read_bit(baseline_bitf).deserialise_chip()

    # Build all per-bit bitstreams upfront
    chips = {}
    for i in range(length):
        bit_vec = [(_ == i) for _ in range(length)]
        print("****** Checking {} bit {} ******".format(name, i))
        bit_bitf = config.build_design(config.ncl, get_ncl_substs(bit_vec), prefix)
        chips[i] = pytrellis.Bitstream.read_bit(bit_bitf).deserialise_chip()

    errors = []

    for tile in config.tiles:
        tdb = tile_dbs[tile]

        try:
            wsb = tdb.get_data_for_word(name)
        except Exception:
            errors.append("MISSING_IN_DB: word setting '{}' not found in database for tile {}".format(name, tile))
            continue

        # Collect all (frame, bit) positions the database records for this word setting
        known_bits = set()
        for bg in wsb.bits:
            for cb in bg.bits:
                known_bits.add((cb.frame, cb.bit))

        base_cram = baseline_chip.tiles[tile].cram

        for i in range(length):
            if i >= len(wsb.bits):
                errors.append("MISSING_BIT: word setting '{}' bit {} out of range (db has {} bits)".format(
                    name, i, len(wsb.bits)))
                continue

            expected_bg = wsb.bits[i]
            cram = chips[i].tiles[tile].cram

            # Check 1: expected bits are correct
            for cb in expected_bg.bits:
                actual = cram.bit(cb.frame, cb.bit)
                want = 0 if cb.inv else 1
                if actual != want:
                    errors.append(
                        "BIT_MISMATCH: {}[{}] tile={} F{}B{}: db_expects={} diamond_got={}".format(
                            name, i, tile, cb.frame, cb.bit, want, actual))

            # Check 2: no extra bits differ vs baseline that the database doesn't know about
            diff = cram - base_cram
            for bit in diff:
                if (bit.frame, bit.bit) not in known_bits:
                    errors.append(
                        "EXTRA_BIT: {}[{}] tile={} F{}B{}: "
                        "bit differs from baseline but not in database for this setting".format(
                            name, i, tile, bit.frame, bit.bit))

    if errors:
        print("MISMATCH: {} — {} discrepancy(s)".format(name, len(errors)))
        for e in errors:
            print("  " + e)
    else:
        print("OK: {} — all {} bit positions match database (both directions)".format(name, length))

    return errors


def fuzz_word_setting(config, name, length, get_ncl_substs, empty_bitfile=None):
    """
    Fuzz a multi-bit setting, such as LUT initialisation

    :param config: FuzzConfig instance containing target device and tile of interest
    :param name: name of the setting to store in the database
    :param length: number of bits in the setting
    :param get_ncl_substs: a callback function, that is first called with an array of bits to create a design with that setting
    :param empty_bitfile: a path to a bit file without the parameter included, optional, which is used to determine the
    default value
    """
    prefix = "thread{}_".format(threading.get_ident())
    tile_dbs = {tile: pytrellis.get_tile_bitdata(
        pytrellis.TileLocator(config.family, config.device, tiles.type_from_fullname(tile))) for tile in
        config.tiles}
    if empty_bitfile is not None:
        none_chip = pytrellis.Bitstream.read_bit(empty_bitfile).deserialise_chip()
    else:
        none_chip = None
    baseline_bitf = config.build_design(config.ncl, get_ncl_substs([False for _ in range(length)]), prefix)
    baseline_chip = pytrellis.Bitstream.read_bit(baseline_bitf).deserialise_chip()

    wsb = {tile: pytrellis.WordSettingBits() for tile in
           config.tiles}
    is_empty = {tile: True for tile in config.tiles}
    for t in config.tiles:
        wsb[t].name = name
    for i in range(length):
        bit_bitf = config.build_design(config.ncl, get_ncl_substs([(_ == i) for _ in range(length)]), prefix)
        bit_chip = pytrellis.Bitstream.read_bit(bit_bitf).deserialise_chip()
        diff = bit_chip - baseline_chip
        for tile in config.tiles:
            if tile in diff:
                wsb[tile].bits.append(pytrellis.BitGroup(diff[tile]))
                is_empty[tile] = False
            else:
                wsb[tile].bits.append(pytrellis.BitGroup())
            if none_chip is not None:
                if wsb[tile].bits[i].match(none_chip.tiles[tile].cram):
                    wsb[tile].defval.append(True)
                else:
                    wsb[tile].defval.append(False)
    for t in config.tiles:
        if not is_empty[t]:
            tile_dbs[t].add_setting_word(wsb[t])
            tile_dbs[t].save()


def fuzz_enum_setting(config, name, values, get_ncl_substs, empty_bitfile=None, include_zeros=True, ignore_cover=None,
                      opt_pref=None, ignore_bits=None):
    """
    Fuzz a setting with multiple possible values

    :param config: FuzzConfig instance containing target device and tile of interest
    :param name: name of the setting to store in the database
    :param values: list of values taken by the enum
    :param get_ncl_substs: a callback function, that is first called with an array of bits to create a design with that setting
    :param empty_bitfile: a path to a bit file without the parameter included, optional, which is used to determine the
    default value
    :param include_zeros: if set, bits set to zero are not included in db. Needed for settings such as CEMUX which share
    bits with routing muxes to prevent conflicts.
    :param ignore_cover: these values will also be checked, and bits changing between these will be ignored
    :param opt_pref: bits exclusively set in these options will be included in all options overriding include_zeros
    """
    prefix = "thread{}_".format(threading.get_ident())
    tile_dbs = {tile: pytrellis.get_tile_bitdata(
        pytrellis.TileLocator(config.family, config.device, tiles.type_from_fullname(tile))) for tile in
        config.tiles}
    if empty_bitfile is not None:
        none_chip = pytrellis.Bitstream.read_bit(empty_bitfile).deserialise_chip()
    else:
        none_chip = None

    changed_bits = set()
    prev_tiles = {}
    tiles_changed = set()
    for val in values:
        print("****** Fuzzing {} = {} ******".format(name, val))
        bit_bitf = config.build_design(config.ncl, get_ncl_substs(val), prefix)
        bit_chip = pytrellis.Bitstream.read_bit(bit_bitf).deserialise_chip()
        for prev in prev_tiles.values():
            for tile in config.tiles:
                diff = bit_chip.tiles[tile].cram - prev[tile]
                if len(diff) > 0:
                    tiles_changed.add(tile)
                    for bit in diff:
                        changed_bits.add((tile, bit.frame, bit.bit))
        prev_tiles[val] = {}
        for tile in config.tiles:
            prev_tiles[val][tile] = bit_chip.tiles[tile].cram
    if ignore_cover is not None:
        ignore_changed_bits = set()
        ignore_prev_tiles = {}
        for ival in ignore_cover:
            print("****** Fuzzing {} = {} [to ignore] ******".format(name, ival))
            bit_bitf = config.build_design(config.ncl, get_ncl_substs(ival), prefix)
            bit_chip = pytrellis.Bitstream.read_bit(bit_bitf).deserialise_chip()
            for prev in ignore_prev_tiles.values():
                for tile in config.tiles:
                    diff = bit_chip.tiles[tile].cram - prev[tile]
                    if len(diff) > 0:
                        for bit in diff:
                            ignore_changed_bits.add((tile, bit.frame, bit.bit))
            ignore_prev_tiles[ival] = {}
            for tile in config.tiles:
                ignore_prev_tiles[ival][tile] = bit_chip.tiles[tile].cram
        for ibit in ignore_changed_bits:
            if ibit in changed_bits:
                changed_bits.remove(ibit)
    for tile in tiles_changed:
        esb = pytrellis.EnumSettingBits()
        esb.name = name
        pref_exclusive = {}
        if opt_pref is not None:
            for val in values:
                for (btile, bframe, bbit) in changed_bits:
                    if btile == tile:
                        state = prev_tiles[val][tile].bit(bframe, bbit)
                        if state:
                            if val in opt_pref:
                                if (btile, bframe, bbit) not in pref_exclusive:
                                    pref_exclusive[(btile, bframe, bbit)] = True
                            else:
                                pref_exclusive[(btile, bframe, bbit)] = False
        for val in values:
            bg = pytrellis.BitGroup()
            for (btile, bframe, bbit) in changed_bits:
                if btile == tile:
                    state = prev_tiles[val][tile].bit(bframe, bbit)
                    if state == 0 and not include_zeros and (
                            none_chip is not None and not none_chip.tiles[tile].cram.bit(bframe, bbit)) \
                            and (
                            (btile, bframe, bbit) not in pref_exclusive or not pref_exclusive[(btile, bframe, bbit)]):
                        continue
                    if ignore_bits is not None and ignore_bits.count((btile, bframe, bbit)):
                        continue
                    cb = pytrellis.ConfigBit()
                    cb.frame = bframe
                    cb.bit = bbit
                    cb.inv = (state == 0)
                    bg.bits.add(cb)
            esb.options[val] = bg
            if none_chip is not None and bg.match(none_chip.tiles[tile].cram):
                esb.defval = val
        tile_dbs[tile].add_setting_enum(esb)
        tile_dbs[tile].save()
