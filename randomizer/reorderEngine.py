# Copyright(c) 2018, Hyungjoon Koo
# Copyright(c) 2021, Honggoo Kang
#####################################################################
#  SoftMark: Software Watermarking via a Binary Function Relocation #
#   (In the Annual Computer SEcurity Applications Conference 2021)  # 
#                                                                   #
#  Author: Honggoo Kang <honggoonin@korea.ac.kr>                    #
#          Cybersecurity@Korea University                           #
#                                                                   #
#  This file can be distributed under the MIT License.              #
#  See the LICENSE.TXT for details.                                 #
#####################################################################


import logging
import random
import constants as C
from reorderInfo import EssentialInfo
from constants import Formats as FMT
import binascii, struct, string
import os, re, sys
import subprocess
import util
from capstone import *
import r2pipe

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'extractor'))
import recognitionEngine as recog

sys.setrecursionlimit(10**7)

class ReorderCore(EssentialInfo):
    def __init__(self, ReorderInfo, report):
        '''
        Generate all essential information for further reordering.
        Note that the size information have included the alignment already.
        :param ReorderInfo:
        '''

        # First construct all essential information for randomization
        EssentialInfo.__init__(self, ReorderInfo)
        self.EI = self.getInfo()
        self.EP = self.EI.getElfParser()
        self.randomizedBBContainer = list()
        self.randLayout = list()
        self.randLayout_usable = list()
        self.randLayout_temp = list()
        self.randLayout_idx = list()
        self.randLayout_size = list()
        self.unusedFunc = list()
        self.usable_FunctionLists = list()
        self.usable_Functionidx = list()
        self.usable_Functionsize = list()
        self.BBLs_cache = dict()
        self.R = report
        self.__recordSummary()

        self.fmt = {FMT.CHAR: "<b", FMT.UCHAR: "<B",
                    FMT.SHORT: "<h", FMT.USHORT: "H",
                    FMT.INT: "<i", FMT.UINT: "<I",
                    FMT.LONG: "<q", FMT.ULONG: "<Q"}


    # Wrapper getters to obtain essential objects
    def getBinary(self):      return self.EI.getBinary()
    def getObjects(self):     return self.EI.getObjects()
    def getFunctions(self):   return self.EI.getFunctions()
    def getBasicBlocks(self): return self.EI.getBasicBlocks()
    def getRandLayout(self):  return self.randLayout
    def getReorderInfo(self): return self.EI
    def getELFParser(self):   return self.EP
    def getRandBBs(self):     return self.randomizedBBContainer
    def getReport(self):      return self.R

    def __recordSummary(self):
        """ Bookkeeping the data of our interest """
        self.R.numObjs = self.EI.numObjects
        self.R.numFuns = self.EI.numFunctions
        self.R.numBBLs = self.EI.numBBs
        self.R.numFixupsText, self.R.numFixupsSpecial = self.getNumFixups(C.SEC_TEXT)
        self.R.numFixupsRodata = self.getNumFixups(C.SEC_RODATA)
        self.R.numFixupsData = self.getNumFixups(C.SEC_DATA)
        self.R.numFixupsRel = self.getNumFixups(C.SEC_DATA_REL)
        self.R.numFixupsInitArray = self.getNumFixups(C.SEC_INIT_ARR)

    def getFormat(self, sz):
        """ Return formats for fixup reference size only """
        if sz == 1: return self.fmt[FMT.CHAR]
        if sz == 2: return self.fmt[FMT.SHORT]
        if sz == 4: return self.fmt[FMT.INT]
        if sz == 8: return self.fmt[FMT.LONG]

    def simulateShuffleBBLs(self, BBLs):
        """
        In case of basic block randomization, finding a possible reordering
          that meets BBL constraints (10 trials by default) as described in the paper
        :param BBLs:
        :return:
        """
        firstBBL = self.EI.getBasicBlock(BBLs[0][0])

        # Exclude BBL shuffling for a hand-written assembly case
        if firstBBL.parent.parent.srcKind == C.SRC_TYPE_ASSEMBLY:
            logging.debug("[Case 0] (F#%2d) Standalone Assembly: %s" \
                          % (firstBBL.parent.idx, BBLs))
            return BBLs

        # If there is a single BBL, no need to shuffle the bucket
        if len(BBLs) == 1:
            logging.debug("[Case 1] (F#%2d) Single BBL: %s" \
                          % (firstBBL.parent.idx, BBLs))
            return BBLs

        # If the size of this function is smaller than 128B, go shuffle it
        if firstBBL.parent.size < 128:
            logging.debug("[Case 2] (F#%2d) %dB < 128B" \
                      % (firstBBL.parent.idx, firstBBL.parent.size))
            random.shuffle(BBLs)
            logging.debug("\t\t%s (Success)", BBLs)
            self.R.entropyBBL.append(len(BBLs))
            return BBLs

        chkFixups = list()
        chkFixupsShortDist = list()
        for idx in sum(BBLs, []):
            BBL = self.EI.getBasicBlock(idx)
            for FI in BBL.Fixups:
                if FI.isRela and FI.derefSz < 4:
                    chkFixupsShortDist.append(FI)
                chkFixups.append(FI)

        # If there is no constraint in the BBL set, go shuffle it
        if len(chkFixupsShortDist) == 0:
            logging.debug("[Case 3] (F#%2d) No short distance fixups (<4B): %s" \
                    % (self.EI.getBasicBlock(BBLs[0][0]).parent.idx, BBLs))
            random.shuffle(BBLs)
            self.R.entropyBBL.append(len(BBLs))
            logging.debug("\t\t%s (Success)", BBLs)
            return BBLs

        import copy
        tryCnt = 0
        originalBBLs = copy.deepcopy(BBLs)
        originalList = sum(originalBBLs, [])

        logging.debug("[Case 4] (F#%2d) Simulation" \
                      % (self.EI.getBasicBlock(BBLs[0][0]).parent.idx))

        while True:
            random.shuffle(BBLs)
            tryCnt += 1

            simulateList = sum(BBLs, [])

            firstRandBBL = self.EI.getBasicBlock(simulateList[0])
            firstRandBBL.testVA = self.EI.getBasicBlock(originalList[0]).VA

            # Compute the VAs when BBLs have been relocated in simulateList
            for idx, bbi in enumerate(simulateList):
                if idx > 0:
                    prevBBL = self.EI.getBasicBlock(simulateList[idx-1])
                    curBBL = self.EI.getBasicBlock(simulateList[idx])
                    curBBL.testVA = prevBBL.testVA + prevBBL.size

            # Compute the refVal of the fixup accordingly
            anyFalseFixupRef = False
            for FI in chkFixupsShortDist:
                bblOffset = FI.VA - FI.parent.VA
                FI.testVA = FI.parent.testVA + bblOffset
                testRefVal = FI.refBB.testVA - (FI.testVA + FI.derefSz)
                if testRefVal <= -128 or testRefVal >= 128:
                    anyFalseFixupRef = True

            if not anyFalseFixupRef:
                logging.debug("\t\t%s (Success after %d attempts)" % (BBLs, tryCnt))
                self.R.entropyBBL.append(len(BBLs))
                return BBLs

            if tryCnt > 10:
                BBLs = copy.deepcopy(originalBBLs)
                logging.debug("\t\t%s (Failed after %d attempts)" % (BBLs, tryCnt))
                return BBLs

    def _generateRandTable(self, granularity=1, reanalyze=0):
        """
        This process has to resolve all constraints to meet
            a) intra-function BB-level randomization
            b) function-level randomization
            c) fallThrough blocks have to move around together
            d) maximum distances between BBLs due to derefSz in the fixup
            e) functions from hand-written assembly
        :return:
        """

        funcLayout = []
        textSection = self.EP.elf.get_section_by_name('.text')
        start_address = textSection.header["sh_offset"]
        end_address = start_address + textSection.header["sh_size"]
        hexdata = binascii.hexlify(self.EP.bin)[2*start_address:2*end_address]
        # The following process discovers any reference pointing to the function outside
        # Such case will be viewed as a single function to satisfy the constraint (d)
        curFunc = self.getFunctions()[0]
        constCtr = 0
        prevMFSet = None

        while curFunc:
            mergedFuncs = set()
            chkBBLs = curFunc.BasicBlocks

            # In case of standalone assembly (e)
            # [Note] Assume that all fixups in the object refer to BBLs within
            if curFunc.parent.srcKind == C.SRC_TYPE_ASSEMBLY:
                while curFunc and curFunc.parent.srcKind == C.SRC_TYPE_ASSEMBLY:
                    mergedFuncs.add(curFunc.idx)
                    curFunc = curFunc.next

            else:
                for curBBL in chkBBLs:
                    if len(curBBL.Fixups) == 0:
                        mergedFuncs.add(curBBL.parent.idx)
                        continue
                    for fixup in curBBL.Fixups:
                        if fixup.type == 0 and fixup.derefSz < 4 and fixup.refBB:
                            funcFixupParent = fixup.parent.parent
                            funcFixupRefParent = fixup.refBB.parent
                            mergedFuncs.add(funcFixupParent.idx)

                            # The reference is pointing to the outside of this function
                            if funcFixupParent.idx != funcFixupRefParent.idx:
                                mergedFuncs.add(funcFixupRefParent.idx)
                                chkBBLs += funcFixupRefParent.BasicBlocks
                                curFunc = self.EI.getFunction(funcFixupRefParent.idx)
                        else:
                            mergedFuncs.add(curBBL.parent.idx)

            MF = sorted(mergedFuncs)

            if len(MF) > 1:
                MF = range(MF[0], MF[-1] + 1)

                # Handling the special case when the current function set has the intersection
                #  of the previous set - should be combined together before further proceeding
                if prevMFSet:
                    overlapped = len(set(MF).intersection(set(prevMFSet)))
                    if overlapped > 0:
                        MF = range(min(min(MF), min(prevMFSet)), max(max(MF), max(prevMFSet)) + 1)
                        funcLayout = [x for x in funcLayout if len(set(MF).intersection(x)) == 0]
                        funcLayout.append(MF)
                    else:
                        funcLayout.append(MF)
                else:
                    funcLayout.append(MF)

                prevMFSet = MF

                if len(set([MF[x + 1] - MF[x] for x in range(len(MF) - 1)])) > 1:
                    logging.critical("\tThe merged function set contains non-consecutive functions")

                #assert (len(set([MF[x + 1] - MF[x] for x in range(len(MF) - 1)])) == 1), \
                #    "The merged function set contains non-consecutive functions"
                constCtr += 1

            else:
                funcLayout.append(MF)
                prevMFSet = MF

            # [Note] Assume that compiler would generate functions close enough to refer from
            #        such BBLs that have short distance references (i.e., -128 <= d < 127)
            #        Otherwise this assumption could be problematic because of a skip-over function
            curFunc = self.EI.getFunction(funcLayout[-1][-1]).next

        logging.debug("\tFunction Layout with Constraints: %s", funcLayout)
        logging.info("\t# of Function Constraints: %d", constCtr)
        if len(sum(funcLayout, [])) != self.EI.numFunctions:
            logging.critical("\t# of Functions: %d VS # of elements in funcLayout: %d " \
                             % (self.EI.numFunctions, len(sum(funcLayout,[]))))

        #assert(len(sum(funcLayout, [])) == self.EI.numFunctions), \
        #    "# of Functions: %d VS # of elements in funcLayout: %d " % \
        #    (self.EI.numFunctions, len(sum(funcLayout,[])))

        '''
        Now reorder the Basic Blocks within each Function Layout
        Similarly canFallThrough BBL constraint (c) can be dealt with (d)
        '''

        isData_exists = False

        directoryName = self.EP.fn + '_watermarkingData/'
        fileName = self.EP.fn.split('/')[-1]+'_usableFunctions.txt'
        isData_exists = os.path.exists(directoryName+fileName)

        if isData_exists == True and reanalyze == 0:
            logging.info("Reading the usable functions...")
            self.usable_FunctionLists, iCFTnum = self.readUsableFunctions(directoryName, fileName, funcLayout)
        
        else:
            logging.info("Reanalyzing the usable functions...")
            self.usable_FunctionLists, iCFTnum = self.reanalyzeFunctions(funcLayout, hexdata)

        if granularity > 0:
            logging.info("Shuffling at the BBL granularity...")

        cnt_usable_Func = 0
        cnt_unused_Func = 0
        cnt_iCFT_Func = 0
        funcBar = util.ProgressBar(len(funcLayout))
        for F in funcLayout:
            BBLs = []

            # If there are multiple functions satisfying (d), merge those BBLs
            # This case can be considered as a bulk of intact BBLs (quite rare though)
            if len(F) > 1:
                mergedBBL = set()
                for f in F:
                    for bbl in self.EI.getFunction(f).BasicBlocks:
                        mergedBBL.add(bbl.idx)
                BBLs.append(sorted(mergedBBL))

            else:
                f = self.EI.getFunction(F[0])
                curBBL = f.BasicBlocks[0]

                # Combine the hasFallThrough BBL with the next one (c)
                while curBBL and f.BasicBlocks[0].idx <= curBBL.idx <= f.BasicBlocks[-1].idx:
                    if not curBBL.hasFallThrough:
                        BBLs.append([curBBL.idx])
                        curBBL = curBBL.next
                    else:
                        tmpBBL = curBBL
                        combined = [curBBL.idx]
                        while tmpBBL.hasFallThrough:
                            tmpBBL = tmpBBL.next
                            combined.append(tmpBBL.idx)
                        BBLs.append(combined)
                        curBBL = tmpBBL.next

            # Initialize default value for granularity == 0
            isUsable = False 
            hasiCFT = False

            # Check if this function is usable or not 
            if BBLs in self.usable_FunctionLists:
                isUsable = True
                if self.usable_FunctionLists.index(BBLs) < iCFTnum:
                    hasiCFT = True

                idxVA = self.usable_Functionidx[self.usable_FunctionLists.index(BBLs)]
                idxSize = self.usable_Functionsize[self.usable_FunctionLists.index(BBLs)]

                if reanalyze == 1:
                    self.randLayout_idx.append(idxVA)
                    self.randLayout_size.append(idxSize)
                else:
                    self.randLayout_idx.insert(0, idxVA)
                    self.randLayout_size.insert(0, idxSize)

            # Simulate transformation that references fit into a single byte distance each other
            if granularity > 0:
                BBLs = self.simulateShuffleBBLs(BBLs)   

            
            if isUsable == True:
                # Append only unique function to usable function list
                if hasiCFT:
                    self.randLayout.append(BBLs)
                    self.randLayout_usable.append(BBLs)
                    cnt_usable_Func += len(F)
                    cnt_iCFT_Func += len(F)
                else:
                    self.randLayout.insert(0, BBLs)
                    self.randLayout_usable.insert(0, BBLs)
                    cnt_usable_Func += len(F)
                
            else:
                self.randLayout.append(BBLs) 
                self.unusedFunc.append(BBLs)
                cnt_unused_Func += len(F)
            funcBar += 1
        funcBar.finish()
        
        logging.info("\t# of Usable Functions: %s", cnt_usable_Func)
        logging.info("\t# of Functions with iCFT: %s", cnt_iCFT_Func)
        logging.info("\t# of Unused Functions: %s", cnt_unused_Func)


        # Reorder the Functions - it is safe because the compartmentalized bulks meet all constraints
        # Select Functions for Watermarking
        GroupNum = len(self.randLayout_usable) / C.WM_PERMUTATION_LEN
        
        if len(self.randLayout_usable) < 3*C.WM_PERMUTATION_LEN:
            GroupNum = 1
        
        for i in range(0, GroupNum):
            globals()['randLayout_wm{}'.format(i + 1)] = list()

        # Watermark permutation create & embedding
        hash_value = C.WM_VALUE
        guide_permutation = util.find_permutation(C.WM_PERMUTATION_LEN, int(hash_value, 16))

        for i in range(0, GroupNum):
            globals()['randLayout_wm{}'.format(i + 1)] = self.randLayout_usable[i * C.WM_PERMUTATION_LEN:(i + 1) * C.WM_PERMUTATION_LEN]
            for idx in guide_permutation:
                self.randLayout_temp.append(globals()['randLayout_wm{}'.format(i + 1)][int(idx) - 1])
        
        self.unusedFunc = self.unusedFunc + self.randLayout_usable[GroupNum*C.WM_PERMUTATION_LEN:]

                                   
        for Func in self.unusedFunc:
            self.randLayout_temp.insert(random.randrange(0, len(self.randLayout_temp) + 1), Func)

        # Apply to original randLayout
        self.randLayout = self.randLayout_temp
        funEntropy = len(self.randLayout)
        self.R.entropyFun = funEntropy

        logging.debug("Shuffling at the FUN granularity...")
        logging.debug("Final Function Layout with Constraints: %s", funcLayout)
        logging.debug("Final BBL Layout with Constraints: %s", self.randLayout)

        # Unnest the nested list containing BBLs
        self.randLayout = reduce(lambda x, y: x + y,
                                reduce(lambda x, y: x + y, self.randLayout, []), [])

        # Maintain BBLs in a randomized order
        self.randomizedBBContainer = [self.EI.getBasicBlock(bbi) for bbi in self.randLayout]

        # Save Data for Watermarking recognition & extraction
        for i in range(1, GroupNum + 1):
            self.saveWatermarkingData(i, globals()['randLayout_wm{}'.format(i)], reanalyze)


    def readUsableFunctions(self, directoryName, fileName, funcLayout):
        """
        If we already have the result of usable function analysis for this binary,
        Read the data
        """
        usable_Functions = list()
        iCFT_Functions = list()
        iCFT_idx = list()
        non_iCFT_idx = list()
        iCFT_size = list()
        non_iCFT_size = list()

        file = open(directoryName + fileName)
        totLine = subprocess.check_output(['wc', '-l', str(directoryName + fileName)]).split(' ')[0]

        funcBar = util.ProgressBar(int(totLine))
        while True:
            BBLs = []
            hasiCFT = False
            line = file.readline().strip()
            if not line: break
            if line.split('\t')[0].split(',')[0] == 'True':
                hasiCFT = True
            
            funcNum = int(line.split('\t')[0].split(',')[1])
            fBBLs = line.split('\t')[1:]    # fBBLs = '1,2', '3'
            for fBBL in fBBLs:
                BBL = []          
                fbbi = fBBL.split(',')  # fbbi = '1', '2'
                for bbi in fbbi:
                    BBL.append(int(bbi))     # BBL = [1, 2]
                BBLs.append(BBL)        # BBLs = [[1, 2], [3]]
                
            if hasiCFT:
                iCFT_Functions.append(BBLs)
                iCFT_idx.append(self.EI.getFunction(funcNum).VA)
                iCFT_size.append(self.EI.getFunction(funcNum).size)

            else:
                usable_Functions.append(BBLs)
                non_iCFT_idx.append(self.EI.getFunction(funcNum).VA)
                non_iCFT_size.append(self.EI.getFunction(funcNum).size)

            funcBar += 1

        self.usable_FunctionLists = iCFT_Functions + usable_Functions

        funcBar.finish()

        # Give priority to Functions having iCFT
        self.usable_Functionidx = iCFT_idx + non_iCFT_idx
        self.usable_Functionsize = iCFT_size + non_iCFT_size
        self.calc_iCFTsize(iCFT_Functions)

        return self.usable_FunctionLists, len(iCFT_Functions)



    def reanalyzeFunctions(self, funcLayout, hexdata):
        """
        If we do not have the result of usable function analysis for this binary,
        or if we need to analyze it again, reanalyze!
        """

        usable_Functions = list()
        iCFT_Functions = list()
        iCFT_idx = list()
        non_iCFT_idx = list()
        iCFT_size = list()
        non_iCFT_size = list()

        funcBar = util.ProgressBar(len(funcLayout))
        directoryName = self.EP.fn + '_watermarkingData/'
        fileName = self.EP.fn.split('/')[-1]+'_usableFunctions.txt'
        if not os.path.exists(directoryName):
            os.makedirs(directoryName)
    
        file = open(directoryName + fileName, 'w+')

        disassembled_hexdata = list()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(binascii.unhexlify(hexdata), 0x400000):
            i_info = dict()
            i_info['addr'] = i.address
            i_info['mnemonic'] = i.mnemonic
            i_info['size'] = len(i.bytes)

            disassembled_hexdata.append(i_info)   

        Check_unusableType = [0, 0]
        size_mnemonic_list = dict()
        for inst in disassembled_hexdata:
            if (str(inst['mnemonic']), str(inst['size'])) in size_mnemonic_list:
                size_mnemonic_list[(str(inst['mnemonic']), str(inst['size']))] += 1
            else:
                size_mnemonic_list[(str(inst['mnemonic']), str(inst['size']))] = 1
        
        for F in funcLayout:
            BBLs = []

            # Considering function constraints
            if len(F) > 1:
                mergedBBL = set()
                for f in F:
                    for bbl in self.EI.getFunction(f).BasicBlocks:
                        mergedBBL.add(bbl.idx)
                BBLs.append(sorted(mergedBBL))

            else:
                f = self.EI.getFunction(F[0])
                curBBL = f.BasicBlocks[0]

                # Combine the hasFallThrough BBL with the next one (c)
                while curBBL and f.BasicBlocks[0].idx <= curBBL.idx <= f.BasicBlocks[-1].idx:
                    if not curBBL.hasFallThrough:
                        BBLs.append([curBBL.idx])
                        curBBL = curBBL.next
                    else:
                        tmpBBL = curBBL
                        combined = [curBBL.idx]
                        while tmpBBL.hasFallThrough:
                            tmpBBL = tmpBBL.next
                            combined.append(tmpBBL.idx)
                        BBLs.append(combined)
                        curBBL = tmpBBL.next

            isUsable = True # Initialize default value for granularity == 0

   
            #logging.info("Func#%s Func VA %s", funcLayout.index(F), self.EI.getFunction(F[0]).VA)
            isUsable, unusableType = self.checkUsable(BBLs, disassembled_hexdata, size_mnemonic_list)
            if not isUsable:
                Check_unusableType[unusableType] += len(F)
            


            if isUsable:
                hasiCFT = False
                hasiCFT = self.checkiCFT(BBLs)
                if hasiCFT:
                    iCFT_Functions.append(BBLs)
                    iCFT_idx.append(self.EI.getFunction(F[0]).VA)
                    iCFT_size.append(self.EI.getFunction(F[0]).size)
                else:
                    usable_Functions.append(BBLs)
                    non_iCFT_idx.append(self.EI.getFunction(F[0]).VA)
                    non_iCFT_size.append(self.EI.getFunction(F[0]).size)

                line = str(hasiCFT) + ',' + str(F[0]) + '\t'
                for BBL in BBLs:
                    for bbi in BBL:
                        line += str(bbi) +  ','
                    line = line[:-1] + '\t'
                file.write(line + '\n')
            funcBar += 1

        funcBar.finish()
        file.close()

        # Give priority to Functions having iCFT
        self.usable_FunctionLists = iCFT_Functions + usable_Functions
        self.usable_Functionidx = iCFT_idx + non_iCFT_idx
        self.usable_Functionsize = iCFT_size + non_iCFT_size

        logging.info("\t# of small unusable functions: %s", Check_unusableType[0])
        logging.info("\t# of not unique functions: %s", Check_unusableType[1])


        return self.usable_FunctionLists, len(iCFT_Functions)
    
    def calc_iCFTsize(self, Functions):
        totSize = 0
        for Func in Functions:
            for BBLs in Func:
                for bbi in BBLs:
                    BBL = self.EI.getBasicBlock(bbi)
                    size = BBL.size
                    totSize += size

        logging.info("\tSize(Byte) of iCFT Functions: %s", totSize)



    def checkiCFT(self, Func):
        textSection = self.EP.elf.get_section_by_name('.text').data()
        registers_list = [  'ax', 'al', 'ah', 
                            'cx', 'cl', 'ch', 
                            'dx', 'dl', 'dh', 
                            'si', 'di', 'sp', 
                            'r8', 'r9', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        for BBLs in Func: 
            for bbi in BBLs: 
                BBL = self.EI.getBasicBlock(bbi)
                secOff = BBL.offsetFromSection
                BBLcode = textSection[secOff:secOff + BBL.size]
                
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                for i in md.disasm(BBLcode, 0x1000):
                    if str(i.mnemonic).startswith('j') or str(i.mnemonic) == 'call':
                        if any(reg in str(i.op_str) for reg in registers_list):
                            return True
        
        return False


    def checkUsable(self, BBLs, disassembled_hexdata, size_mnemonic_list):
        firstBBL = self.EI.getBasicBlock(BBLs[0][0])

        # [Case 1]
        # Exclude BBL shuffling for a hand-written assembly case
        if firstBBL.parent.parent.srcKind == C.SRC_TYPE_ASSEMBLY:
            return False, 0
        # Exclude Function with a single BBL
        if len(BBLs) == 1:
            return False, 0
       
        # Check function uniqueness
        pattern = ""
        allBBLs = list()
        Candidates_inst_num = list()
        BBLspattern = self.findREpattern(BBLs, needFuncdata=False)

        bbi = 0
        for BBLpattern in BBLspattern: #BBLpattern: i.mnemonics,i.bytelen\t i.mnemonics,i.bytelen
            Instpatterns = BBLpattern.split('\t')[:-1] 

            if BBLpattern in self.BBLs_cache:
                for BBL in self.BBLs_cache[BBLpattern]:
                    allBBLs.append((bbi, (long(BBL[0]), long(BBL[1]))))

            else:
                cache_data = list()
                this_size_mnemonic_list = dict()
                for Instpattern in Instpatterns:
                    if (Instpattern.split(',')[0], Instpattern.split(',')[1]) in size_mnemonic_list:
                        this_size_mnemonic_list[(Instpattern.split(',')[0], Instpattern.split(',')[1])] = size_mnemonic_list[(Instpattern.split(',')[0], Instpattern.split(',')[1])]

                start_mnemonic_size = [point for point in this_size_mnemonic_list if this_size_mnemonic_list[point] == min(this_size_mnemonic_list.values())]
                
                for mnemonic_size in start_mnemonic_size:
                    startPoints = list()
                    for inst in disassembled_hexdata:
                        if (str(inst['mnemonic']), str(inst['size'])) == mnemonic_size:
                            startPoints.append(inst) 

                    relative_idx = Instpatterns.index(str(mnemonic_size[0]+','+str(mnemonic_size[1])))
                    cnt = 0
                    for point in startPoints:
                        isBBL, start_address, end_address = recog.findinstChain(point, disassembled_hexdata, Instpatterns, relative_idx)
                        if isBBL:
                            cnt += 1
                            
                            allBBLs.append((bbi, (start_address, end_address)))
                            cache_data.append((start_address, end_address))

                self.BBLs_cache[BBLpattern] = cache_data

            bbi += 1
            
        # Finish to collect allBBLs
        # [Case] Exclude identical functions (considering shuffling)
        Candidates_num = list()
        for bbi in range(0, len(BBLspattern)):
            cnt = len(filter(lambda bbl: bbl[0] == bbi, allBBLs))
            Candidates_num.append((bbi, cnt))
        
        Candidates_num.append((bbi, cnt))

        allBBLs.sort(key = lambda element : element[1][0])

        isAnalysis = True
        for bbi_cnt in Candidates_num: # bbi_cnt: (bbi, cnt)
            if bbi_cnt[1] == 1:
                result = recog.findChain_bidirection(bbi_cnt, allBBLs, len(BBLspattern), isAnalysis=True)
                if result == 1:
                    return True, 2
        cnt_list = [bbi_cnt[1] for bbi_cnt in Candidates_num]
        min_cnt_bbi = [bbi_cnt for bbi_cnt in Candidates_num if bbi_cnt[1] == min(cnt_list)]

        for bbi_cnt in min_cnt_bbi:
            result = recog.findChain_bidirection(bbi_cnt, allBBLs, len(BBLspattern), isAnalysis=True)
            if result == 1:
                return True, 2
            else:
                return False, 1


    def findREpattern(self, Func, needFuncdata=False):
        textSection = self.EP.elf.get_section_by_name('.text').data()
        wm_BBLs = list()
        BBLcnt = 0
        Instcnt = 0
        funcSize = 0

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        for BBLs in Func: 
                wm_BBL = ""

                for bbi in BBLs: 
                    BBLcnt += 1 # Counting basic blocks
                    BBL = self.EI.getBasicBlock(bbi)
                    secOff = BBL.offsetFromSection
                    BBLcode = textSection[secOff:secOff + BBL.size]
                    
                    for i in md.disasm(BBLcode, 0x1000):
                        wm_BBL += str(i.mnemonic)+','+str(len(i.bytes))+'\t'
                        Instcnt += 1
                        funcSize += len(BBLcode)
                        # Using capstone disassembler to count instructions
                        
                wm_BBLs.append(wm_BBL)
        
        if needFuncdata:
            return funcSize, BBLcnt, Instcnt, wm_BBLs
        else:
            return wm_BBLs

    def saveWatermarkingData(self, idx, randLayout_wm, reanalyze=0):

        textSection = self.EP.elf.get_section_by_name('.text')
        start_address = textSection.header["sh_offset"]
        end_address = start_address + textSection.header["sh_size"]

        wmData = str(start_address) + '\t' + str(end_address)+ '\n'
        wmData += "FUNC_NUM    FUNC_Sz  BBLcode_list    BBLsNum     InstNum"
        cnt = 1

        # watermarking data for RE pattern comparison
        directoryName = self.EP.fn + '_watermarkingData/'
        fileName = self.EP.fn.split('/')[-1]+'_wm'+str(idx)+'_extractData.txt'
        if not os.path.exists(directoryName):
            os.makedirs(directoryName)
        
        f = open(directoryName  + fileName, 'w')
        for Func in randLayout_wm: 
            wmData = wmData + '\nFUNC#' + str(cnt) + '\t' #+ str(len(Func)) + '\t'
            Func_Sz = 0
            Func_Sz, BBLcnt, Instcnt, wm_BBLs = self.findREpattern(Func, needFuncdata=True)

            wmData = wmData + str(Func_Sz) + '\t' + str(wm_BBLs) + '\t' + str(BBLcnt) + '\t' + str(Instcnt)
            cnt += 1
    
        f.write(wmData)
        f.close()
        
        if reanalyze == 1:
            fileName = self.EP.fn.split('/')[-1]+'_wm'+str(idx)+'_lookupData.txt'
            f = open(directoryName + fileName, 'w')
            idxData = ''
            #for Func in randLayout_wm:
            for i in range(0, C.WM_PERMUTATION_LEN):
                func_idx = self.randLayout_idx[((idx - 1) * C.WM_PERMUTATION_LEN) + i]
                func_size = self.randLayout_size[((idx - 1) * C.WM_PERMUTATION_LEN) + i]
                idxData += str(func_idx) + ',' + str(func_size) + '\t'

            f.write(idxData)
            f.close()


    def performTransformation(self, granularity=0, reanalyze=0):
        """
        Once the randomized layout is determined, references require to be recomputed accordingly
        This method contains one of the core reordering processes.
            a) Update new VAs of the randomized BBLs (or functions)
            b) Update all fixups in [.rodata|.data.rel.ro|.data] sections
                according to randomized functions and/or basic blocks in .text section
        :param DEBUG:
        :return:
        """
        # Prepare for a lookup table to contain the order of randomized BBs
        # TODO - Later, this has to be used for de-randomization
        self._generateRandTable(granularity, reanalyze)

        # [Step 1] Set the first basic block after randomization
        beginOffset = self.EI.getBasicBlocks()[0].offsetFromBase
        firstRandBBL = self.randomizedBBContainer[0]
        base = firstRandBBL.VA - firstRandBBL.offsetFromBase
        firstRandBBL.newOffsetFromSection = beginOffset
        firstRandBBL.newVA = base + firstRandBBL.newOffsetFromSection
        firstRandBBL.adjustedBytes = firstRandBBL.newVA - firstRandBBL.VA

        # [Step 2] Set the following basic blocks accordingly: newVA, adjustedBytes
        for idx, bbi in enumerate(self.randLayout):
            if idx > 0:
                prevBBL = self.EI.getBasicBlock(self.randLayout[idx - 1])
                BBL = self.EI.getBasicBlock(bbi)
                BBL.newOffsetFromSection = prevBBL.newOffsetFromSection + prevBBL.size
                BBL.newVA = base + BBL.newOffsetFromSection
                BBL.adjustedBytes = BBL.newVA - BBL.VA


        # [Step 3] Compute newOffset, newRefVal, newVA and newRefTo in .text section
        jumpTables = dict() # VA: (numJTEntries, jtEntrySz)
        if self.hasFixupsInText():
            for FI in self.getFixupsText():
                # For the fixups in standalone assembly, just skip them to update
                if FI.parent.parent.parent.srcKind == C.SRC_TYPE_ASSEMBLY:
                    continue

                # For fixups in .text, newVA needs to be updated
                FIOffsetBBL = FI.VA - FI.parent.VA
                FI.newVA = FI.parent.newVA + FIOffsetBBL
                FI.newOffset = FI.newVA - base

                # If the fixup contains the absolute address and C2C type,
                # update it to the reordered address (pointing to the original BBL)
                # otherwise leave it as it is. (C2D type)
                if not FI.isRela:
                    if FI.type == C.FT_C2C:
                        try:
                            FI.newRefVal = FI.refBB.newVA
                            FI.newRefTo = FI.newRefVal
                        except AttributeError:
                            # Exception when any orphan fixup exists
                            FI.newRefVal = FI.newRefTo = FI.refTo
                            logging.warning("\t(%s) [Possibly CFI/LTO] Check out Fixup [%d] RefBB: %s, newRefTo: 0x%x, Type: %d" % \
                                             (C.SEC_TEXT, FI.idx, FI.refBB, FI.newRefVal, FI.type))
                    else:
                        FI.newRefVal = FI.derefVal
                        FI.newRefTo = FI.refTo

                else:
                    # FI.VA + refVal + derefSz = RefTo
                    # newRefVal = RefTo - FI.newVA - derefSz
                    FI.newRefTo = FI.refBB.newVA if FI.refBB else FI.refTo
                    FI.newRefVal = FI.newRefTo - FI.newVA - FI.derefSz

                # The following information will be used to update entries in .rodata
                if FI.numJTEntries > 0:
                    jumpTables[FI.refTo] = (FI.parent.parent, FI.numJTEntries, FI.jtEntrySz)

        def updateFixupRefs1(fixups, secName, jumpTables):
            """ Update the fixups for .rodata and .data.rel.ro sections """
            pivot, numJTEntries, jtEntrySz = 0x0, 0, 0
            for FI in fixups:
                if FI.type == C.FT_D2D:    # Do not touch the case of D2D
                    FI.newRefVal = FI.derefVal
                    FI.newRefTo = FI.refTo
                    continue

                # If the fixup corresponds to any jump table
                if FI.VA in jumpTables:
                    pivot = FI.VA
                    fixupFunc, numJTEntries, jtEntrySz = jumpTables[pivot]

                # If the fixup contains absolute value, it is straightforward to update
                if not FI.isRela:
                    try:
                        FI.newRefVal = FI.refBB.newVA
                        FI.newRefTo = FI.newRefVal
                        logging.debug("\t(%s) Fixup [%d] RefBB: %s, RefVal: 0x%x, RefTo: 0x%x, Type: %d" % \
                                      (secName, FI.idx, FI.refBB, FI.newRefVal, FI.newRefTo, FI.type))

                        '''
                        # [NEW] For cross reference trace, use the jump table (indirect pointers)
                        if pivot <= FI.VA < pivot + (numJTEntries * jtEntrySz):
                            refFunc = self.EI.getBBlByVA(FI.derefVal).parent
                            fixupFunc.refTos.add(refFunc)
                            refFunc.refFroms.add(fixupFunc)
                        '''

                    except AttributeError:
                        # Exception when any orphan fixup exists
                        FI.newRefVal = FI.newRefTo = FI.refTo
                        logging.warning("\t(%s) [Possibly CFI/LTO] Check out Fixup [%d] RefBB: %s, newRefVal: 0x%x, Type: %d" % \
                                        (secName, FI.idx, FI.refBB, FI.newRefVal, FI.type))

                # If the fixup contains relative value [RV] (pie/pic)
                #    a) non-JT: newRV = BBL(VA + RV).newVA - VA
                #    b) JT:     newRV = BBL(pivot + RV).newVA - pivot (where pivot = JT location)
                # PIE/PIC (position independent) binary falls into this category
                else:
                    # If Fixup is the entry of this jump table, adjust the relative value accordingly
                    if pivot <= FI.VA < pivot + (numJTEntries * jtEntrySz):
                        FI.newRefTo = self.EI.getBBlByVA(pivot + FI.derefVal).newVA
                        FI.newRefVal = FI.newRefTo - pivot
                        logging.debug("\t(%s) [PIE] Fixup@0x%x: RV=0x%x, Pivot=0x%x, newRefTo=0x%x, newRefVal=0x%x"
                                     % (secName, FI.VA, FI.derefVal, pivot, FI.newRefTo, FI.newRefVal))

                        '''
                        # [NEW] For cross reference trace, use the jump table (indirect pointers)
                        refFunc = self.EI.getBBlByVA(pivot + FI.derefVal).parent
                        fixupFunc.refTos.add(refFunc)
                        refFunc.refFroms.add(fixupFunc)
                        '''

                    else:
                        FI.newRefTo = self.EI.getBBlByVA(FI.VA + FI.derefVal).newVA
                        FI.newRefVal = FI.newRefTo - FI.VA
                        logging.debug("\t(%s) [PIE] Fixup@0x%x: RV=0x%x, newRefTo=0x%x, newRefVal=0x%x"
                                     % (secName, FI.VA, FI.derefVal, FI.newRefTo, FI.newRefVal))

        # [Step 4] Compute newRefVal and newRefTo in .rodata/.data.rel.ro section
        if self.hasFixupsInRodata():
            updateFixupRefs1(self.getFixupsRodata(), C.SEC_RODATA, jumpTables)

        if self.hasFixupsInDataRel():
            updateFixupRefs1(self.getFixupsDataRel(), C.SEC_DATA_REL, jumpTables)

        # FIXME - Did not combine updateFixupRefs2 with updateFixupRefs1 for better readability
        def updateFixupRefs2(fixups, secName):
            """ Update the fixups for .data and .init_array sections """
            for FI in fixups:
                if FI.type == C.FT_D2D and secName is not C.SEC_INIT_ARR:    # Do not touch the case of D2D
                    FI.newRefVal = FI.derefVal
                    FI.newRefTo = FI.refTo
                    continue

                if not FI.isRela:
                    try:
                        FI.newRefVal = FI.refBB.newVA
                        FI.newRefTo = FI.newRefVal
                        logging.debug("\t(%s) Fixup [%d] RefBB: %s, RefVal: 0x%x, RefTo: 0x%x, Type: %d" % \
                                    (secName, FI.idx, FI.refBB, FI.newRefVal, FI.newRefTo, FI.type))
                    except AttributeError:
                        # Exception when any orphan fixup exists
                        FI.newRefVal = FI.newRefTo = FI.refTo
                        additionalMsg = ' [Possibly CFI / LTO]' if not secName == C.SEC_INIT_ARR else ''
                        logging.warning("\t(%s)%s Check out Fixup [%d] RefBB: %s, newRefTo: 0x%x, Type: %d" % \
                                        (secName, additionalMsg, FI.idx, FI.refBB, FI.newRefVal, FI.type))
                else:
                    # Have not found any case that falls into this category
                    # All fixup entries in .data seems absolute addresses even under PIE
                    logging.critical("\t(%s) Relative fixup in this section?! [NEW]" % (secName))
                    pass

        # [Step 5] Compute newRefVal and newRefTo in the following sections: .data and .init_array
        if self.hasFixupsInData():
            updateFixupRefs2(self.getFixupsData(), C.SEC_DATA)
        if self.hasFixupsInInitArray():
            updateFixupRefs2(self.getFixupsInitArray(), C.SEC_INIT_ARR)

    def showRandLayout(self):
        """ Show the randomized layout and all updated fixups accordinly """
        def showFixups(allFixups, secName):
            logging.info('Fixups in %s section' % (secName))
            for FI in allFixups:
                logging.info(FI)
                logging.info("\t==> newVal=0x%08x, newRefTo=0x%08x" % (FI.newRefVal, FI.newRefTo))

        logging.info('Code Layout in a Randomized Binary in Details')
        for idx in self.randLayout:
            BBL = self.EI.getBasicBlock(idx)
            logging.info(BBL)
            logging.info("\t==> newSecOff=0x%08x, newVA=0x%08x (Adj %3dB)" \
                         % (BBL.newOffsetFromSection, BBL.newVA, BBL.adjustedBytes))
            for FI in BBL.Fixups:
                logging.info(FI)
                logging.info("\t\t==>@0x%08x, newSecOff=0x%04x, newRefVal=0x%08x, newRefTo=0x%08x" \
                             % (FI.newVA, FI.newOffset, FI.newRefVal, FI.newRefTo))

        if self.hasFixupsInRodata():
            showFixups(self.getFixupsRodata(), C.SEC_RODATA)

        if self.hasFixupsInData():
            showFixups(self.getFixupsData(), C.SEC_DATA)

        if self.hasFixupsInDataRel():
            showFixups(self.getFixupsDataRel(), C.SEC_DATA_REL)

        if self.hasFixupsInInitArray():
            showFixups(self.getFixupsInitArray(), C.SEC_INIT_ARR)
