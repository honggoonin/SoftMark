# Copyright(c) 2018, Hyungjoon Koo
# Copyright(c) 2021, Honggoo Kang
#####################################################################
#  SoftMark: Software Watermarking via a Binary Function Relocation #
#   (In the Annual Computer Security Applications Conference 2021)  # 
#                                                                   #
#  Author: Honggoo Kang <honggoonin@korea.ac.kr>                    #
#          Cybersecurity@Korea University                           #
#                                                                   #
#  This file can be distributed under the MIT License.              #
#  See the LICENSE.TXT for details.                                 #
#####################################################################

import os, sys
import logging
import constants as C 
import util
import binascii, re, subprocess
from capstone import *

sys.setrecursionlimit(10**7)

def findFunc(target_path, Func_RErules, sectionsize):
    funcBar = util.ProgressBar(len(Func_RErules))

    isFail = False
    FoundFunc = list()
    with open(target_path, 'rb') as f:
        textSection_startAddr = int(sectionsize[0])
        textSection_endAddr = int(sectionsize[1])

        # Focus on .text section
        hexdata = binascii.hexlify(f.read())[2*textSection_startAddr:2*textSection_endAddr]

    disassembled_hexdata = list()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(binascii.unhexlify(hexdata), 0x400000):
        i_info = dict()
        i_info['addr'] = i.address
        i_info['mnemonic'] = i.mnemonic
        i_info['size'] = len(i.bytes)

        disassembled_hexdata.append(i_info)  

    size_mnemonic_list = dict()
    for inst in disassembled_hexdata:
        if (str(inst['mnemonic']), str(inst['size'])) in size_mnemonic_list:
            size_mnemonic_list[(str(inst['mnemonic']), str(inst['size']))] += 1
        else:
            size_mnemonic_list[(str(inst['mnemonic']), str(inst['size']))] = 1

    BBL_cache = dict()
    for FuncNum in range(1, C.WM_PERMUTATION_LEN + 1):
        FuncOff = 0

        allBBLs = list()
        BBLsNum = len(Func_RErules[FuncNum])
        Candidates_Num = list()

        BBLpatterns = Func_RErules[FuncNum] # for multiple BBLs
        bbi = 0
        for Instpatterns in BBLpatterns:
            '''
                Instpatterns: ['mov,5', 'mov,5', 'mov,5', 'mov,5', 'call,5', 'nop,13']
                Instruction list for a BBL
            '''
            strInstpatterns = str(Instpatterns)
        
            cnt = 0
            if strInstpatterns in BBL_cache:
                for BBL in BBL_cache[strInstpatterns]:
                    allBBLs.append((bbi, (int(BBL[0]), int(BBL[1]))))
                    cnt += 1

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
                    for point in startPoints:
                        isBBL, start_address, end_address = findinstChain(point, disassembled_hexdata, Instpatterns, relative_idx)
                        if isBBL:
                            allBBLs.append((bbi, (start_address, end_address))) 
                            cache_data.append((start_address, end_address))      
                            cnt += 1

                BBL_cache[strInstpatterns] = cache_data
            Candidates_Num.append((bbi, cnt))
            bbi += 1

        '''
        allBBLs: all BBL candidates from RE pattern search
        BBLsNum: # of BBLs in a function
        '''
        allBBLs.sort(key = lambda element : element[1][0])

        # [Case 1] Found a BBL with one search result(candidate)
        hasUniqueResult = False
        hasFuncoff = False
        for bbi_cnt in Candidates_Num:
            if bbi_cnt[1] == 1:
                hasUniqueResult = True
                result = findChain_bidirection(bbi_cnt, allBBLs, BBLsNum, isAnalysis=False)
                if result != 0:
                    FuncOff = result[0][1][0]
                    hasFuncoff = True
                    break

        # [Case 2] All BBLs have multiple search result. Need to find BBL with minimum search result
        if not hasUniqueResult and not hasFuncoff:
            logging.info('\tTrying to find BBL chain again...')
            cnt_list = [bbi_cnt[1] for bbi_cnt in Candidates_Num]
            min_cnt_bbi = [bbi_cnt for bbi_cnt in Candidates_Num if bbi_cnt[1] == min(cnt_list)]
            for bbi_cnt in min_cnt_bbi:
                result = findChain_bidirection(bbi_cnt, allBBLs, BBLsNum, isAnalysis=False)
                #logging.info('result %s len %s', result, len(result))
                if result != 0:
                    FuncOff = result[0][1][0]
                    hasFuncoff = True
                    break

        # [Case 3] Something Wrong...
        if not hasFuncoff:
            logging.info('\tBasic block missing... Takes more time...')
            FuncOff = callfindChain(allBBLs, BBLsNum)
        
        if FuncOff != 0:
            Func_data = (FuncNum, FuncOff)
            FoundFunc.append(Func_data)

        else:
            candidates_list = list()
            candidates_list = findCandidates(allBBLs, BBLsNum, candidates_list)
            if not candidates_list:
                isFail = True
                break
            
            elif len(candidates_list) == 1:
                Funcoff = candidates_list[0][0][0]
                Func_data = (FuncNum, Funcoff)
                FoundFunc.append(Func_data)

            else:
                candidates_len = [len(candidate) for candidate in candidates_list]
                candidates = [candidate for candidate in candidates_list if len(candidate) == max(candidates_len)]
                
                if len(candidates) == 1:
                    Funcoff = candidates[0][0][0]
                    Func_data = (FuncNum, Funcoff)
                    FoundFunc.append(Func_data)

                else:
                    isFail = True
                    break 
        funcBar += 1           

    funcBar.finish()
    return FoundFunc, isFail


def lookupFunc(target_path, Funcidx_List):
    import r2pipe

    funcBar = util.ProgressBar(len(Funcidx_List))

    target_path = os.path.dirname(os.path.abspath(__file__))[:-9] + target_path
    FoundFunc = [0 for i in range(C.WM_PERMUTATION_LEN)]
    isFail = False

    abs_path = os.path.dirname(os.path.abspath(__file__))
    mb_path = target_path[:-9]# master binary path
    r = r2pipe.open(mb_path)
    r.cmd('aaa')
    mb_symbol_table = dict()
    func_list = r.cmd('afl').strip()

    for func in func_list.split('\n'):
        VA = int(func.split()[0][2:], 16)
        name = func.split()[-1]
        mb_symbol_table[VA] = name

    r.quit()

    r2 = r2pipe.open(target_path)
    r2.cmd('aaa')

    target_symbol_table = dict()
    target_func_list = r2.cmd('afl').strip()
 
    for target_func in target_func_list.split('\n'):
        VA = int(target_func.split()[0][2:], 16)
        name = target_func.split()[-1]
        target_symbol_table[name] = VA

    r2.quit()

    for idxsize in Funcidx_List:
        idx = idxsize[0]
        size = idxsize[1]
        func_num = Funcidx_List.index(idxsize) + 1

        foundVA = target_symbol_table[mb_symbol_table[int(idx)]]
        logging.info(mb_symbol_table[int(idx)])
        FoundFunc[func_num - 1] = (func_num, foundVA)

        funcBar += 1


    funcBar.finish()
    return FoundFunc, isFail


def Inst_endaddr(Inst):
    return Inst[1]['addr']+Inst[1]['size']


def findinstChain(Inst, disassembled_hexdata, Instpatterns, relative_idx):
    # inst: (idx, (i.mnemonic, i.bytelen))

    start_idx = disassembled_hexdata.index(Inst) - relative_idx
    isDone = True
    startAddr = disassembled_hexdata[start_idx]['addr']
    endAddr = disassembled_hexdata[start_idx]['addr']

    for i in range(0, len(Instpatterns)):
        if i == len(Instpatterns) - 1:
            compare_size = int(Instpatterns[i].split(',')[1])
            endAddr += compare_size
            if int(disassembled_hexdata[start_idx+i]['size']) != compare_size:
                isDone = False 
                break 
        else:
            compare_mnemonic = Instpatterns[i].split(',')[0]
            compare_size = int(Instpatterns[i].split(',')[1])
            endAddr += compare_size

            if disassembled_hexdata[start_idx+i]['mnemonic'] != compare_mnemonic or int(disassembled_hexdata[start_idx+i]['size']) != compare_size:
                isDone = False
                break
    return isDone, startAddr, endAddr
    

# Find BBLs Chain ion bidirection way (using findChain_right, findChain_left)
def findChain_bidirection(bbi_cnt, allBBLs, BBLsNum, isAnalysis=False):
    BBLs = list()
    diff_allBBLs = list()
    Chain_Num = 0

    final_result = list()

    for x in allBBLs:
        if x[0] == bbi_cnt[0]:
            BBLs.append(x)
        else:
            diff_allBBLs.append(x)

    for BBL in BBLs:
        listBBL = list()
        listBBL.append(BBL)

        result_right = findChain_right(listBBL, diff_allBBLs)

        used_idx = [result[0] for result in result_right]
        left_diff_allBBLs = [diffBBLs for diffBBLs in allBBLs if diffBBLs[0] not in used_idx]
        result_left = findChain_left(listBBL, left_diff_allBBLs)


        result = result_left[:-1] + result_right
        if isAnalysis:
            if len(result) == BBLsNum:
                Chain_Num += 1
                if Chain_Num > 1:
                    break
        else:
            if len(result) == BBLsNum:
                return result

    return Chain_Num




def callfindChain(allBBLs, BBLsNum):

    if not allBBLs:
        return 0

    # BBL = (bbi, (start, end))
    BBL = allBBLs[0]
    listBBL = list()
    listBBL.append(BBL)

    diff_allBBLs = [diffBBLs for diffBBLs in allBBLs if diffBBLs[0] != BBL[0]]
    result = findChain_right(listBBL, diff_allBBLs)

    if len(result) == BBLsNum:
        FuncOff = result[0][1][0]
        return FuncOff

    else:
        new_allBBLs = allBBLs[1:]
        return callfindChain(new_allBBLs, BBLsNum)

# BBL is list
# ex. [(bbi, (1, 2))]
def findChain_right(BBL, allBBLs): 
    nextBBLs = [bbl for bbl in allBBLs if bbl[1][0] == BBL[0][1][1]]

    if not nextBBLs:
        return BBL
 
    elif len(nextBBLs) > 1:
        doneList = list()
        candidates = list()

        for nextBBL in nextBBLs:
            if nextBBL[1][1] not in doneList:
                listnextBBL = list()
                listnextBBL.append(nextBBL)
                diff_allBBLs = [diffBBLs for diffBBLs in allBBLs if diffBBLs[0] != nextBBL[0]]
                candidates.append(BBL + findChain_right(listnextBBL, diff_allBBLs))
                doneList.append(nextBBL[1][1])
        candidates_len = [len(candidate) for candidate in candidates]
        return candidates[candidates_len.index(max(candidates_len))]
        
    else:
        diff_allBBLs = [diffBBLs for diffBBLs in allBBLs if diffBBLs[0] != nextBBLs[0][0]]
        return BBL + findChain_right(nextBBLs, diff_allBBLs)

def findChain_left(BBL, allBBLs): 
    nextBBLs = [bbl for bbl in allBBLs if bbl[1][1] == BBL[0][1][0]]
    
    if not nextBBLs:
        return BBL
 
    elif len(nextBBLs) > 1:
        doneList = list()
        candidates = list()
        for nextBBL in nextBBLs:
            if nextBBL[1][0] not in doneList:
                listnextBBL = list()
                listnextBBL.append(nextBBL)
                diff_allBBLs = [diffBBLs for diffBBLs in allBBLs if diffBBLs[0] != nextBBL[0]]
                candidates.append(findChain_left(listnextBBL, diff_allBBLs) + BBL)
                doneList.append(nextBBL[1][0])
        candidates_len = [len(candidate) for candidate in candidates]
        return candidates[candidates_len.index(max(candidates_len))]
        
    else:
        diff_allBBLs = [diffBBLs for diffBBLs in allBBLs if diffBBLs[0] != nextBBLs[0][0]]
        return findChain_left(nextBBLs, diff_allBBLs) + BBL

def findCandidates(allBBLs, BBLsNum, candidates_list):
    if not allBBLs:
        return candidates_list

    BBL = allBBLs[0]
    listBBL = list()
    listBBL.append(BBL)

    result = findChain_right(listBBL, allBBLs)
    
    if len(result) >= 3:
        candidates_list.append(result)
        
    new_allBBLs = [BBLs for BBLs in allBBLs if BBLs not in result]
    return findCandidates(new_allBBLs, BBLsNum, candidates_list)

