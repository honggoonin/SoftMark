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

import math
import util
import os, sys
import logging
import constants as C 
import subprocess
import pathlib

def getInfo(watermarkData_path, lookup):

    if lookup:
        Funcidx_List = list()
        infoBar = util.ProgressBar(C.WM_PERMUTATION_LEN)

        with open(watermarkData_path, 'r') as file:
            line = file.readline()
            idxsize_list = line.split('\t')
            for idxsize in idxsize_list:
                Funcidx_List.append(idxsize.split(','))
                infoBar += 1
        return Funcidx_List[:-1]


    else:
        Func_BBLcodes = dict()
        FuncSz_List = list()
        textSection_size = list()
        BBLcnt_List = list()
        Instcnt_List = list()

        totLine = subprocess.check_output(['wc', '-l', str(pathlib.Path().absolute()) + os.sep + watermarkData_path]).decode('utf-8').split(' ')[0]
        
        with open(watermarkData_path, 'r') as file:
            infoBar = util.ProgressBar(int(totLine))

            line = None
            line = file.readline() # textSection size information
            textSection_size = line.split('\t')
            infoBar += 1
            
            line = file.readline() # Ignore first line of data
            while True: 
                line = file.readline().strip('\n')
                if line =='': break
                infoBar += 1

                words = line.split('\t')
                FuncNum = int(words[0].split('#')[1])
                FuncSz = int(words[1])
                BBLcnt = int(words[3])
                Instcnt = int(words[4])

                FuncSz_List.append(FuncSz)
                BBLcnt_List.append(BBLcnt)
                Instcnt_List.append(Instcnt)


                BBLcode_String = list(words[2][1:-1].split(', ')) # Remove outer brackets 
                BBLcodes = list()
                
                for BBL in BBLcode_String:
                    BBLcode = BBL[1:-1].split('\\t')[:-1]
                    BBLcodes.append(BBLcode)
                
                Func_BBLcodes[FuncNum] = BBLcodes

        logging.debug('Func_BBLcodes: %s', Func_BBLcodes)

        infoBar.finish()
        return Func_BBLcodes, FuncSz_List, textSection_size, BBLcnt_List, Instcnt_List

def findWatermark(element_permutation, N): 
	findwmBar = util.ProgressBar(N)

	check = [False]*(N+1) 
	ans = 0
	cout = ''
	for i in range(0, N):
		for j in range(1, int(element_permutation[i])): 
			if check[j] == False:
				ans += math.factorial(N - i - 1)
		check[int(element_permutation[i])] = True

		findwmBar += 1
	
	cout = ans + 1
	
	findwmBar.finish()

	return cout

