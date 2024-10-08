################################################################
#  Compiler-assisted Code Randomization: Practical Randomizer  #
#   (In the 39th IEEE Symposium on Security & Privacy 2018)    #
#                                                              #
#  Author: Hyungjoon Koo <hykoo@cs.stonybrook.edu>             #
#          Computer Science@Stony Brook University             #
#                                                              #
#  This file can be distributed under the MIT License.         #
#  See the LICENSE.TXT for details.                            #
################################################################

import os, sys
import logging
import gzip
import shuffleInfo_pb2
import constants as C

def deserializeInfo(ri):
    """ Deserialze the metadata from compiler and linker """
    def dumpFixups(F, section, fixupsBag):
        """
        :param F: Fixups from ReorderInfo binary
        :param section: Could be either .text, .rodata or .data
        :param fixupsBag: list() of all fixupInfo attributes
        :return:
        """
        if len(F) > 0:
            '''
            FixupTuple has been defined as following in shuffleInfo.proto
            message FixupTuple {
              required uint32 offset = 1;         // UPDATE AT LINKTIME WHEN COMBINING SECTIONS
              required uint32 deref_sz = 2;
              required bool   is_rela = 3;
              optional uint32 type = 4;           // (c2c,c2d,d2c,d2d) = range(3)
              optional string section_name = 5;   // section identifier in c++ mutiple sections
                                                  // fixup has a jump table (.rodata) for pic/pie use
              optional uint32 num_jt_entries = 6; // number of the jump table entries
              optional uint32 jt_entry_sz = 7;    // size of each jump table entry in byte
            }
            '''
            specialFixupCtr = 0
            specialFixupComment = ""
            for i in range(len(F)):
                # Only .text section might have jump table information for JT update with pic/pie
                if section == C.SEC_TEXT:
                    fixupEntry = (F[i].offset, F[i].deref_sz, F[i].is_rela, F[i].type, F[i].num_jt_entries, F[i].jt_entry_sz)
                    if F[i].type == 5:
                        specialFixupCtr += 1
                else:
                    fixupEntry = (F[i].offset, F[i].deref_sz, F[i].is_rela, F[i].type)
                fixupsBag.append(fixupEntry)

            if specialFixupCtr > 0:
                specialFixupComment = "(" + str(specialFixupCtr) + " in special sections)"
            logging.info("\tFixups in %s\t: %d %s" %
                         (section, len(F) - specialFixupCtr, specialFixupComment))

    dataset = dict()
    obj = ri.bin
    bblLayout = ri.layout
    fixups = ri.fixup
    srcTypes = ri.source

    obj_sz, fn_sz, bbl_sz = [], [], []
    objLayout, funLayout, FixupCnts = [], [], []  #fn/obj, #bbl/fn
    canFallThroughs = []

    fsz, osz = 0, 0
    bid, fid, oid = 0, 0, 0
    bb_ctr, fn_ctr = 0, 0

    # Expand the BBL layout to binary, object, function and basic blocks
    # It feeds the EssentialInfo to construct a single hierarchical tree structure
    # Entries of each layer constitute a doubly linked list structure
    for idx in range(len(bblLayout)):
        '''
        LayoutInfo has been defined as following in shuffleInfo.proto
          message LayoutInfo {
            optional uint32 bb_size = 1;          // UPDATE AT LINKTIME WITH OBJ ALIGNMENTs
                                                  // All alignments between fn/bbl are included here
            optional uint32 type = 2;             // Represents the end of [OBJ|FUN|BBL] = range(2)
            optional uint32 num_fixups = 3;       // Number of fixups within this basic block
            optional bool bb_fallthrough = 4;     // Can this basic block be fallen through the next?
          }
        '''
        sz = bblLayout[idx].bb_size
        type = bblLayout[idx].type
        numFixups = bblLayout[idx].num_fixups
        canFallThrough = bblLayout[idx].bb_fallthrough

        bbl_sz.append(sz)

        fsz += sz
        osz += sz

        bb_ctr += 1
        bid += 1
        FixupCnts.append(numFixups)
        canFallThroughs.append(canFallThrough)

        if type >= 1:       # End of the function the BBL belongs to
            fn_sz.append(fsz)
            funLayout.append(bb_ctr)
            fn_ctr += 1
            bid = 0
            fid += 1
            fsz, bb_ctr = 0, 0

        if type == 2:       # End of the object the BBL belongs to
            obj_sz.append(osz)
            objLayout.append(fn_ctr)
            fid = 0
            oid += 1
            osz, fn_ctr = 0, 0

    # [FIXME] Ugly, but just a workaround
    # Function information is somehow disappeared from LTO...
    # In case of LTO, objLayout and obj_sz need to be adjusted
    if len([bblLayout[x].type for x in range(len(bblLayout)) if bblLayout[x].type == 1]) == 0:
        assert (len(objLayout) == len(obj_sz))
        idxes = list()
        for i in range(len(objLayout)):
            if objLayout[i] > 1:
                idxes.append(i)

        adjustedLayout = list()
        adjustedSz = list()
        start = 0
        for j in idxes:
            adjustedLayout.append(sum(objLayout[start:j]))
            adjustedLayout.append(objLayout[j])
            adjustedSz.append(sum(obj_sz[start:j]))
            adjustedSz.append(obj_sz[j])
            start = j + 1

        adjustedLayout.append(sum(objLayout[start:]))
        adjustedSz.append(sum(obj_sz[start:]))
        objLayout, obj_sz = adjustedLayout, adjustedSz

    '''
    BinaryInfo has been defined as following in shuffleInfo.proto
      message BinaryInfo {
        optional uint32 rand_obj_offset = 1;     // PLACEHOLDER FOR LINKER
        optional uint32 main_addr_offset = 2;    // PLACEHOLDER FOR LINKER
        optional uint32 obj_sz = 3;              // Verification purpose
      }
    '''
    dataset['bin_info'] = {}
    dataset['bin_info']['reorderObjStartFromText'] = obj.rand_obj_offset
    dataset['bin_info']['mainAddrOffsetFromText']  = obj.main_addr_offset
    dataset['bin_info']['reorderedObjSize'] = obj.obj_sz

    # The info for Objects and Functions is derived from LayoutInfo
    dataset['obj_size'] = obj_sz
    dataset['obj_func_cnt'] = objLayout
    dataset['func_size'] = fn_sz
    dataset['func_bb_cnt'] = funLayout
    dataset['bb_size'] = bbl_sz
    dataset['bb_fixup_cnt'] = FixupCnts
    dataset['bb_fall_through'] = canFallThroughs

    assert (sum(obj_sz) == sum(fn_sz) == sum(bbl_sz)), "Does not match objSz, FnSz, and BBLSz!"

    logging.info('Reading the metadata from the .rand section...')
    logging.info('\tOffset to the object  : 0x%02x', obj.rand_obj_offset)
    logging.info('\tOffset to the main()  : 0x%02x', obj.main_addr_offset)
    logging.info('\tTotal Emitted Bytes   : 0x%04x' % sum(obj_sz))
    logging.info('\tNumber of Objects     : %d' % len(obj_sz))
    logging.info('\tNumber of Functions   : %d' % len(fn_sz))
    logging.info('\tNumber of Basic Blocks: %d' % len(bbl_sz))

    # Fixups in .text has to point its parent BBL, which consist of leaves in the tree
    fixupsText, fixupsRodata, fixupsData, fixupsDataRel, fixupsInitArray = [], [], [], [], []
    for fi in range(len(fixups)):
        dumpFixups(fixups[fi].text, C.SEC_TEXT, fixupsText)
        dumpFixups(fixups[fi].rodata, C.SEC_RODATA, fixupsRodata)
        dumpFixups(fixups[fi].data, C.SEC_DATA, fixupsData)
        dumpFixups(fixups[fi].datarel, C.SEC_DATA_REL, fixupsDataRel)
        dumpFixups(fixups[fi].initarray, C.SEC_INIT_ARR, fixupsInitArray)

    def __getDataSet(fixups, kind):
        if len(fixups) > 0:
            #print(zip(*fixups))
            #print(list(zip(*fixups)))
            #print(kind)
            return list(zip(*fixups))[kind]
            #return list(zip(*fixups)[kind])
        else:
            return []

    def _collectDataSet(DS_FIXUP, fixups):
        for i, DS in enumerate(DS_FIXUP):
            dataset[DS] = __getDataSet(fixups, i)

    _collectDataSet(C.DS_FIXUP_TEXT, fixupsText)
    _collectDataSet(C.DS_FIXUP_RODATA, fixupsRodata)
    _collectDataSet(C.DS_FIXUP_DATA, fixupsData)
    _collectDataSet(C.DS_FIXUP_DATAREL, fixupsDataRel)
    _collectDataSet(C.DS_FIXUP_INIT_ARR, fixupsInitArray)

    dataset['obj_src_type'] = srcTypes.src_type

    logging.info('\tNumber of Jump Tables : %d' %
                 len([x for x in dataset['fixup_num_jt_entries'] if x!=0]))

    return dataset

def readOnly(outFile, randInfo):
    def printFixups(F, sec):
        if len(F) > 0:
            out.write("Fixups in %s: %d\n" % (sec, len(F)))
            for i in range(len(F)):
                isRela = 'Y' if F[i].is_rela else 'N'
                ty = C.FIXUP_TYPE[F[i].type]
                secName = F[i].section_name
                JTEntries, JTEntrySz = F[i].num_jt_entries, F[i].jt_entry_sz
                out.write("\tFixup#%4d [%s] - Off:0x%04x, DerefSz:%d, IsRela:%s, Type: %s (@Sec %s)" % \
                      (i, sec, F[i].offset, F[i].deref_sz, isRela, ty, secName))
                if sec == C.SEC_TEXT and JTEntries > 0:
                    out.write(", [JT] %d Entries with %dB in size\n" % (JTEntries, JTEntrySz))
                else:
                    out.write("\n")

    obj = randInfo.bin
    bblLayout = randInfo.layout
    fixups = randInfo.fixup
    srcTypes = randInfo.source

    out = open(outFile, 'w')
    out.write("Main Addr Offset   : 0x%04x\n" % obj.main_addr_offset)
    out.write("Rand Object Offset : 0x%04x\n" % obj.rand_obj_offset)
    out.write("Rand Object Size   : 0x%04x\n" % obj.obj_sz)
    out.write("Total BBLs in .text: %d\n" % len(bblLayout))

    fallThroughCtr = 0
    for idx in range(len(bblLayout)):
        sz = bblLayout[idx].bb_size
        type = C.BBL_TYPE[bblLayout[idx].type]
        numFixups = bblLayout[idx].num_fixups
        if bblLayout[idx].bb_fallthrough:
            canFallThrough = "Y"
            fallThroughCtr += 1
        else:
            canFallThrough = "N"
        secName = bblLayout[idx].section_name
        out.write("\tBBL#%4d (%3dB) [%s] - Fixups: %2d, FallThrough: %s (@Sec %s)\n" % \
                 (idx, sz, type, numFixups, canFallThrough, secName))

    for fi in range(len(fixups)):
        printFixups(fixups[fi].text, C.SEC_TEXT)
        printFixups(fixups[fi].rodata, C.SEC_RODATA)
        printFixups(fixups[fi].data, C.SEC_DATA)
        printFixups(fixups[fi].datarel, C.SEC_DATA_REL)
        printFixups(fixups[fi].initarray, C.SEC_INIT_ARR)

    numObjs = len(srcTypes.src_type)
    if numObjs > 0:
        out.write("Total Objects: %d\n" % (numObjs))
        for j in range(numObjs):
            ty = srcTypes.src_type[j]
            if ty > 0:
                out.write("\tObj %d: %s\n" % (j, C.SRC_TYPE[ty]))
    else:
        logging.critical("The metadata does not contain the type of an object (obsolete ver?)")

    out.close()
    print("\tMain Addr Offset   : 0x%04x" % obj.main_addr_offset)
    print("\tRand Object Offset : 0x%04x" % obj.rand_obj_offset)
    print("\tRand Object Size   : 0x%04x" % obj.obj_sz)
    print("\tTotal BBLs in .text: %d" % len(bblLayout))
    #print "\tTotal BBLs in .text: %d (Fallthrough = %d, %.2f%%)" \
    #      % (len(bblLayout), fallThroughCtr, fallThroughCtr / float(len(bblLayout)) * 100)
    print("Wrote the metadata to %s..." % outFile)

def read(metaData, hasRandSection):
    """
    Deserialize the metadata for randomization in google protobuf format
    :param metaData: target file name
    :param isDebug:
    :return:
    """
    randInfo = shuffleInfo_pb2.ReorderInfo()
    if hasRandSection:
        try:
            randInfo.ParseFromString(gzip.open(metaData, "rb").read())
        except IOError:
            print("Found a .rand section but not gzipped. Check out the CCR linker!")
    else:
        randInfo.ParseFromString(open(metaData, "rb").read())
    return deserializeInfo(randInfo)

if __name__ == '__main__':
    def isELF(f):
        # Check if the magic number is "\x7F ELF"
        return open(f, 'rb').read(4) == '\x7f\x45\x4c\x46'

    def isGzipped(f):
        # Check if the magic number is "\x1f \x8b"
        return open(f, 'rb').read(2) == '\x1f\x8b'

    def isMetadata(f):
        return f.endswith(C.METADATA_POSTFIX)

    def getMetadata(param):
        if isMetadata(param):
            print("Found the metadata at %s" % param)
            return param
        if isELF(param):
            if os.path.exists(C.METADATA_PATH):
                os.remove(C.METADATA_PATH)
            os.system(' '.join(['objcopy', '--dump-section',
                               C.RAND_SECTION + '=' + C.METADATA_PATH, param, '2> /dev/null']))
            return C.METADATA_PATH

    fn = getMetadata(sys.argv[1])
    ri = shuffleInfo_pb2.ReorderInfo()

    if isMetadata(fn):
        ri = shuffleInfo_pb2.ReorderInfo()
        ri.ParseFromString(open(fn, "rb").read())
        readOnly(fn + C.METADESC_POSTFIX, ri)
    elif isELF(sys.argv[1]):
        try:
            bin_str = gzip.open(fn, "rb").read() if isGzipped(fn) else open(fn, "rb").read()
            ri.ParseFromString(bin_str)
            print("Found the .rand section, dumping into %s (will be removed at the end)" % C.METADATA_PATH)
            readOnly(sys.argv[1] + C.METADATA_POSTFIX + C.METADESC_POSTFIX, ri)
            os.remove(C.METADATA_PATH)
        except IOError:
            print("The ELF binary does not contain a .rand section for metadata!")
    else:
        print("Usage:", sys.argv[0], "<filename.shuffle.bin> or <ELF format with a .rand section>")