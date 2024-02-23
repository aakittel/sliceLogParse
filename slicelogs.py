import argparse
import glob
import gzip
import os
from datetime import datetime
"""
 NetApp / SolidFire
 CPE 
 sf-slice log parse utility
"""
"""
Add start and end timestamp option
"""
"""
BUGS

  File "/data/user/akittel/slicelogs.py", line 351, in <module>
    messages_found = log_search(contents)
                     ^^^^^^^^^^^^^^^^^^^^
  File "/data/user/akittel/slicelogs.py", line 105, in log_search
    get_sense(message)
  File "/data/user/akittel/slicelogs.py", line 53, in get_sense
    sense_code = words[-1].split('0x')[1]
                 ~~~~~~~~~~~~~~~~~~~~~^^^
IndexError: list index out of range
"""

def get_args():
    cmd_args = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    cmd_args.add_argument('-p', '--prefix', help='Specify a output file prefix')
    required_named = cmd_args.add_argument_group('required named arguments')
    required_named.add_argument('-d', '--directory', required=True, help='Specify the log bundle parent directory')
    required_named.add_argument('-v', '--volumeid', required=True, help='Specify the volumeID')
    return cmd_args.parse_args()

#============================================================
# Recursively find all required log files
def find_logs(args, prefix="sf-slice"):
    print(f'find {args.directory}/logs/{prefix}*')
    result = []
    result = glob.glob(f'{args.directory}/logs/{prefix}*')
    if result:    
        return result
    else:
        print(f'Could not find any {prefix} files')

#============================================================
# Open a file and return contents as a list
def open_file_return_list(filename):
    contents = []
    print(f'Opening {filename}')
    if os.path.isfile(filename):
        if 'gz' in filename:
            f = gzip.open(filename, "r")
            c = f.readlines()
            f.close()
            for line in c:
                contents.append(line.decode("utf-8"))
            del(c)
        else:
            f = open(filename, "r")
            contents = f.readlines()
            f.close()
        return contents
    else:
        print(f'Cannot open {filename}\n')   

#============================================================
# Parse message line for scsi sense codes
def get_sense(line):
    words = line.split()
    try:
        if "=0x=" in words[-1]:
            sense_code = f'0x{words[-1].split("0x")[2]}'
        else:
            sense_code = words[-1].split('0x')[1]
        for sense in sense_codes:
            if sense_code in sense.lower():
                sense_codes_found.add(sense)
    except:
        print(f'Error while parsing {words[-1]}')

#============================================================
# Get the sessionID
def get_session_id(message):
    words = message.split()
    for word in words:
        if 'sessionID' in word:
            id = word.split('=')[1]
            session_id.add(id)
            
#============================================================
# Get aborts
def get_abort(message):
    words = message.split()
    for word in words:
        if 'mAbortReason=' in word and word != 'mAbortReason=None':
            abort_reason.add(word)

#============================================================
# Get shutdowns
def get_shutdown(message):
    words = message.split()
    for word in words:
        if 'shutdownReason' in word and word != 'shutdownReason=None':
            shutdown_reason.add(word)

#============================================================
# Get initiators
def get_initiator(message):
    words = message.split()
    for word in words:
        if 'initiatorPortName' in word:
            id = word.split('=')[1]
            initiators.add(id)

#============================================================
# Get offline volumes
#The following volumes are offline            

#============================================================
# Parse the /var/run/log files
def log_search(contents):
    messages_found = []
    for search_string in grep_dict:
        print(f'\tSearching for {search_string}')
        for message in contents:
            if search_string in message and f'volumeID={args.volumeid}' in message:
                messages_found.append(message)
                grep_dict[f'{search_string}'] +=1
                get_initiator(message)
                get_session_id(message)
                get_abort(message)
                if search_string == "SendCommandCheckConditionResponse" or search_string == "SendCommandErrorResponse":
                    get_sense(message)
    if messages_found is not None:
        return messages_found
    
grep_dict = {
    "FIRST WRITE SCSITask": 0,
    "FIRST READ SCSITask": 0,
    "WRITE FAILED": 0,
    "READ FAILED": 0,
    "xCompareFailed": 0,
    "SendCommandCheckConditionResponse": 0,
    "SendCommandErrorResponse": 0,
    "DESTRUC": 0,
    "Destroyed": 0,
    "CONSTRUCT": 0,
    "FullFeature": 0,
    "REDIRECT": 0,
    "live-to-dead": 0,
    "Overdue heartbeat": 0,
    "Heartbeat response returned an error", 0
}

sense_reference = "https://en.wikipedia.org/wiki/Key_Code_Qualifier"
sense_codes_found = set()
session_id = set()
abort_reason = set()
shutdown_reason = set()
initiators = set()

sense_codes = [
    "00000 No error",
    "05D00 No sense - PFA threshold reached",
    "10100 Recovered Write error - no index",
    "10200 Recovered no seek completion",
    "10300 Recovered Write error - write fault",
    "10900 Track following error",
    "10B01 Temperature warning",
    "10C01 Recovered Write error with auto-realloc - reallocated",
    "10C03 Recovered Write error - recommend reassign",
    "11201 Recovered data without ECC using prev logical block ID",
    "11202 Recovered data with ECC using prev logical block ID",
    "11401 Recovered Record Not Found",
    "11600 Recovered Write error - Data Sync Mark Error",
    "11601 Recovered Write error - Data Sync Error - data rewritten",
    "11602 Recovered Write error - Data Sync Error - recommend rewrite",
    "11603 Recovered Write error - Data Sync Error - data auto-reallocated",
    "11604 Recovered Write error - Data Sync Error - recommend reassignment",
    "11700 Recovered data with no error correction applied",
    "11701 Recovered Read error - with retries",
    "11702 Recovered data using positive offset",
    "11703 Recovered data using negative offset",
    "11705 Recovered data using previous logical block ID",
    "11706 Recovered Read error - without ECC, auto reallocated",
    "11707 Recovered Read error - without ECC, recommend reassign",
    "11708 Recovered Read error - without ECC, recommend rewrite",
    "11709 Recovered Read error - without ECC, data rewritten",
    "11800 Recovered Read error - with ECC",
    "11801 Recovered data with ECC and retries",
    "11802 Recovered Read error - with ECC, auto reallocated",
    "11805 Recovered Read error - with ECC, recommend reassign",
    "11806 Recovered data using ECC and offsets",
    "11807 Recovered Read error - with ECC, data rewritten",
    "11C00 Defect List not found",
    "11C01 Primary defect list not found",
    "11C02 Grown defect list not found",
    "11F00 Partial defect list transferred",
    "14400 Internal target failure",
    "15D00 PFA threshold reached",
    "20400 Not Ready - Cause not reportable.",
    "20401 Not Ready - becoming ready",
    "20402 Not Ready - need initialise command (start unit)",
    "20403 Not Ready - manual intervention required",
    "20404 Not Ready - format in progress",
    "20409 Not Ready - self-test in progress",
    "23100 Not Ready - medium format corrupted",
    "23101 Not Ready - format command failed",
    "23502 Not Ready - enclosure services unavailable",
    "23A00 Not Ready - medium not present",
    "23A01 Not Ready - medium not present - tray closed",
    "23A02 Not Ready - medium not present - tray open",
    "23A03 Not Ready - medium not present - loadable",
    "23A04 Not Ready - medium not present - medium auxiliary memory accessible",
    "24C00 Diagnostic Failure - config not loaded",
    "30200 Medium Error - No Seek Complete",
    "30300 Medium Error - write fault",
    "31000 Medium Error - ID CRC error",
    "31100 Medium Error - unrecovered read error",
    "31101 Medium Error - read retries exhausted",
    "31102 Medium Error - error too long to correct",
    "31104 Medium Error - unrecovered read error - auto re-alloc failed",
    "3110B Medium Error - unrecovered read error - recommend reassign",
    "31401 Medium Error - record not found",
    "31600 Medium Error - Data Sync Mark error",
    "31604 Medium Error - Data Sync Error - recommend reassign",
    "31900 Medium Error - defect list error",
    "31901 Medium Error - defect list not available",
    "31902 Medium Error - defect list error in primary list",
    "31903 Medium Error - defect list error in grown list",
    "3190E Medium Error - fewer than 50% defect list copies",
    "33100 Medium Error - medium format corrupted",
    "33101 Medium Error - format command failed",
    "40100 Hardware Error - no index or sector",
    "40200 Hardware Error - no seek complete",
    "40300 Hardware Error - write fault",
    "40900 Hardware Error - track following error",
    "41100 Hardware Error - unrecovered read error in reserved area",
    "41501 Hardware Error - Mechanical positioning error",
    "41600 Hardware Error - Data Sync Mark error in reserved area",
    "41900 Hardware Error - defect list error",
    "41902 Hardware Error - defect list error in Primary List",
    "41903 Hardware Error - defect list error in Grown List",
    "43200 Hardware Error - no defect spare available",
    "43500 Hardware Error - enclosure services failure",
    "43501 Hardware Error - unsupported enclosure function",
    "43502 Hardware Error - enclosure services unavailable",
    "43503 Hardware Error - enclosure services transfer failure",
    "43504 Hardware Error - enclosure services refused",
    "43505 Hardware Error - enclosure services checksum error",
    "43E00 Hardware Error - logical unit has not self configured yet",
    "43E01 Hardware Error - logical unit failed",
    "43E02 Hardware Error - timeout on logical unit",
    "43E03 Hardware Error - self-test failed",
    "43E04 Hardware Error - unable to update self-test log",
    "44400 Hardware Error - internal target failure",
    "51A00 Illegal Request - parm list length error",
    "52000 Illegal Request - invalid/unsupported command code",
    "52100 Illegal Request - LBA out of range",
    "52400 Illegal Request - invalid field in CDB (Command Descriptor Block)",
    "52500 Illegal Request - invalid LUN",
    "52600 Illegal Request - invalid fields in parm list",
    "52601 Illegal Request - parameter not supported",
    "52602 Illegal Request - invalid parm value",
    "52603 Illegal Request - invalid field parameter - threshold parameter",
    "52604 Illegal Request - invalid release of persistent reservation",
    "52C00 Illegal Request - command sequence error",
    "53501 Illegal Request - unsupported enclosure function",
    "54900 Illegal Request - invalid message",
    "55300 Illegal Request - media load or eject failed",
    "55301 Illegal Request - unload tape failure",
    "55302 Illegal Request - medium removal prevented",
    "55500 Illegal Request - system resource failure",
    "55501 Illegal Request - system buffer full",
    "55504 Illegal Request - Insufficient Registration Resources",
    "62800 Unit Attention - not-ready to ready transition (format complete)",
    "62900 Unit Attention - POR or device reset occurred",
    "62901 Unit Attention - POR occurred",
    "62902 Unit Attention - SCSI bus reset occurred",
    "62903 Unit Attention - TARGET RESET occurred",
    "62904 Unit Attention - self-initiated-reset occurred",
    "62905 Unit Attention - transceiver mode change to SE",
    "62906 Unit Attention - transceiver mode change to LVD",
    "62A00 Unit Attention - parameters changed",
    "62A01 Unit Attention - mode parameters changed",
    "62A02 Unit Attention - log select parms changed",
    "62A03 Unit Attention - Reservations pre-empted",
    "62A04 Unit Attention - Reservations released",
    "62A05 Unit Attention - Registrations pre-empted",
    "62F00 Unit Attention - commands cleared by another initiator",
    "63F00 Unit Attention - target operating conditions have changed",
    "63F01 Unit Attention - microcode changed",
    "63F02 Unit Attention - changed operating definition",
    "63F03 Unit Attention - inquiry parameters changed",
    "63F04 Unit Attention - component device attached",
    "63F05 Unit Attention - device identifier changed",
    "63F06 Unit Attention - redundancy group created or modified",
    "63F07 Unit Attention - redundancy group deleted",
    "63F08 Unit Attention - spare created or modified",
    "63F09 Unit Attention - spare deleted",
    "63F0A Unit Attention - volume set created or modified",
    "63F0B Unit Attention - volume set deleted",
    "63F0C Unit Attention - volume set deassigned",
    "63F0D Unit Attention - volume set reassigned",
    "63F0E Unit Attention - reported LUNs data has changed",
    "63F0F Unit Attention - echo buffer overwritten",
    "63F10 Unit Attention - medium loadable",
    "63F11 Unit Attention - medium auxiliary memory accessible",
    "63F12 Unit Attention - iSCSI IP address added",
    "63F13 Unit Attention - iSCSI IP address removed",
    "63F14 Unit Attention - iSCSI IP address changed",
    "63F15 Unit Attention - inspect referrals sense descriptors",
    "63F16 Unit Attention - microcode has been changed without reset",
    "63F17 Unit Attention - zone transition to full",
    "63F18 Unit Attention - bind completed",
    "63F19 Unit Attention - bind redirected",
    "63F1A Unit Attention - subsidiary binding changed",
    "65D00 Unit Attention - PFA threshold reached",
    "72002 Access Denied - No Access Rights",
    "72700 Write Protect - command not allowed",
    "B0000 Aborted Command - no additional sense code",
    "B1B00 Aborted Command - sync data transfer error (extra ACK)",
    "B2500 Aborted Command - unsupported LUN",
    "B3F0F Aborted Command - echo buffer overwritten",
    "B4300 Aborted Command - message reject error",
    "B4400 Aborted Command - internal target failure",
    "B4500 Aborted Command - Selection/Reselection failure",
    "B4700 Aborted Command - SCSI parity error",
    "B4800 Aborted Command - initiator-detected error message received",
    "B4900 Aborted Command - inappropriate/illegal message",
    "B5503 Aborted Command - insufficient resources",
    "B4B00 Aborted Command - data phase error",
    "B4E00 Aborted Command - overlapped commands attempted",
    "B4F00 Aborted Command - due to loop initialisation",
    "E1D00 Miscompare - during verify byte check operation",
    "x0500 Illegal Request",
    "x0600 Unit Attention",
    "x0700 Data protect",
    "x0800 LUN communication failure",
    "x0801 LUN communication timeout",
    "x0802 LUN communication parity error",
    "x0803 LUN communication CRC error",
    "x0900 vendor specific sense key",
    "x0901 servo fault",
    "x0904 head select fault",
    "x0A00 error log overflow",
    "x0B00 Aborted Command",
    "x0C00 write error",
    "x0C02 write error - auto-realloc failed",
    "x0E00 data miscompare",
    "x1200 address mark not found for ID field",
    "x1400 logical block not found",
    "x1500 random positioning error",
    "x1501 mechanical positioning error",
    "x1502 positioning error detected by read of medium",
    "x2700 write protected",
    "x2900 POR or bus reset occurred",
    "x3101 format failed",
    "x3201 defect list update error",
    "x3202 no spares available",
    "x3501 unspecified enclosure services failure",
    "x3700 parameter rounded",
    "x3D00 invalid bits in identify message",
    "x3E00 LUN not self-configured yet",
    "x4001 DRAM parity error",
    "x4002 DRAM parity error",
    "x4200 power-on or self-test failure",
    "x4C00 LUN failed self-configuration",
    "x5C00 RPL status change",
    "x5C01 spindles synchronised",
    "x5C02 spindles not synchronised",
    "x6500 voltage fault",
    "x≥80x Vendor specific",
    "xx≥80 Vendor specific",
    "0x18 Reservation conflict",
    "0x28 Task Set Full",
    "0x40 Task Aborted"
    ]


if __name__ == "__main__":
    args = get_args()
    logs = find_logs(args)
    report = []
    for filename in logs:
        report.append(f'\n{filename}\n')
        contents = open_file_return_list(filename)
        messages_found = log_search(contents)
        if messages_found is not None:
            report.append(messages_found)

    date_time = datetime.now()
    time_stamp = date_time.strftime("%d-%b-%Y-%H.%M.%S")
    if args.prefix is None:
        summary_file = f'{args.volumeid}-summary-{time_stamp}.txt'
        messages_file = f'{args.volumeid}-messages-{time_stamp}.txt'
    else:
        summary_file = f'{args.prefix}-{args.volumeid}-summary-{time_stamp}.txt'
        messages_file = f'{args.prefix}-{args.volumeid}-messages-{time_stamp}.txt'
    
    print(f'\nWriting report to {summary_file}')
    with open(summary_file, '+w') as outputfile:
        outputfile.write("++ Initiators found\n")
        for item in initiators:
            outputfile.write(f'{item}\n')
        outputfile.write("\n++ Sense codes found\n")
        for item in sense_codes_found:
            outputfile.write(f'{item}\n')
        outputfile.write("\n++ Sessions found\n")
        for item in session_id:
            outputfile.write(f'{item}\n')
        outputfile.write("\n++ Aborts found\n")
        for item in abort_reason:
            outputfile.write(f'{item}\n')
        outputfile.write("\n++ Shutdowns found\n")
        for item in shutdown_reason:
            outputfile.write(f'{item}\n')
        outputfile.write("\n++ Counts\n")
        for key in grep_dict:
            outputfile.write(f'{key}: {grep_dict[key]}\n')
    
    print(f'Writing report to {messages_file}')
    with open(messages_file, 'w') as outputfile:
        for item in report:
            outputfile.writelines(item)
