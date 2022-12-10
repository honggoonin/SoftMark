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

import os, time
import logging
import optparse
import util
import recognitionEngine
import constants as C
import wmReader

def extractWatermarkImpl(target_path, watermarkData_path, lookup):
    """
    This function contains full extraction process step by step    
    """

    startTime = time.time()

    # Read the watermarking extraction data in a given data file
    logging.info("Reading data for extraction...")
    if lookup:
        Funcidx_List = list()
        Funcidx_List = wmReader.getInfo(watermarkData_path, lookup=True)
    else:
        Func_BBLcodes = dict()
        Func_BBLcodes, FuncSz_List, textSection_size, BBLcnt_List, Instcnt_List = wmReader.getInfo(watermarkData_path, lookup=False)


    # Function Recognition process
    logging.info("Finding Functions by BBLcodes...")
    FoundFunc = list()
    isFail = bool()
    if lookup:
        FoundFunc, isFail = recognitionEngine.lookupFunc(target_path, Funcidx_List)
    else:
        FoundFunc, isFail = recognitionEngine.findFunc(target_path, Func_BBLcodes, textSection_size)

    if isFail:
        logging.info("Fail to find all functions from Binary...")

    else:
        FoundFunc.sort(key = lambda element : element[1])
        FoundFuncidx = [x[0] for x in FoundFunc]

        # Watermark Extraction based on Function permutation
        logging.info("Check Watermark from function permutation...")
        watermarknum = wmReader.findWatermark(FoundFuncidx, C.WM_PERMUTATION_LEN)

        logging.info("Watermark Extracted")
        logging.info("\t%s", hex(watermarknum))
        

    endTime = time.time()
    logging.info("Total elapsed time: %s", util._show_elapsed(startTime, endTime))


def extractWatermark(target, watermarkData, lookup):
    """ Trigger watermark extraction """
    if "Data" in watermarkData:
        extractWatermarkImpl(target, watermarkData, lookup)
    else:
        logging.info("[Invalid Data] Need appropriate datafile for Watermark Extraction")

def isValidArgs(args):
    """ Check if arguments are valid to proceed """
    if len(args) == 0:
        parser.error("No input file")
        return False
    if len(args) == 1:
        parser.error("Missing input file or watermarking data file")
        return False
    if len(args) > 2:
        parser.error("Too much files")
        return False

    input = args[0]
    if not os.path.exists(input):
        print "The target file [%s] has not been found!", input
        return False

    input2 = args[1]
    if not os.path.exists(input2):
        print "The watermark data file [%s] has not been found!", input2
        return False    

    return True

if __name__ == '__main__':

    print(C.LOGO)
    usage = "Usage: %prog [-g] <BinaryFilePath> <WatermarkDataFilePath> (Use -h for help)"
    #usage = "Usage: %prog [-g|-l] <BinaryFilePath> <WatermarkDataFilePath> (Use -h for help)"

    parser = optparse.OptionParser(usage=usage, version=C.VERSION)

    parser.add_option("-g", "--debug", dest="debug", action="store_true", default=False,
                      help="Debugging mode for recognition engine")

    # Need to Fix
    parser.add_option("-l", "--lookup", dest="lookup", action="store_true", default=False,
                      help="Look up based function search for non-modified binary")

    (options, args) = parser.parse_args()

    if isValidArgs(args):
        fp = args[0]
        wmdfp = args[1]

        logPath = wmdfp[:-16] + C.LOG_POSTFIX
        if os.path.exists(logPath):
            os.remove(logPath)

        if options.debug:
            logging.basicConfig(filename=logPath, level=logging.DEBUG)
        else:
            logging.basicConfig(filename=logPath, level=logging.INFO)

        rootLogger = logging.getLogger()
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(util.ColorFormatter())
        rootLogger.addHandler(consoleHandler)

        extractWatermark(fp, wmdfp, options.lookup)
        logging.info("Finish!! The log has been saved to %s", logPath)