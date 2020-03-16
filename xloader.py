#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Author: Krzysztof Markiewicz
# 2019-2020, www.obbo.pl
#
# This program is distributed under the terms of the GNU General Public License v3.0
#

from enum import Enum
import getopt 
import logging
import os 
import sys

  
class MessageFormatter(logging.Formatter):
    FORMATS = {
        logging.INFO: '%(message)s',
        'DEFAULT': '[%(levelname)s]: %(message)s',
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS['DEFAULT'])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)   
   
class Message(object):
    def __init__(self):
        self._silent = False
        self.logger = logging.getLogger(__name__)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(MessageFormatter())
        logging.root.addHandler(handler)
        logging.root.setLevel(logging.INFO)
                
    def set_level(self, level):
        self.logger.setLevel(level)

    def set_silent(self, state):
        self._silent = state
                
    def show(self, level, message):  
        if not(self._silent):
            if level == 'DEBUG':
                self.logger.debug(message)
            elif level == 'WARNING':
                self.logger.warning(message)
            elif level == 'ERROR':
                self.logger.error(message)
            elif level == 'CRITICAL':
                self.logger.critical(message)
            else:
                self.logger.info(message)
                
message = Message() 

class ProgressBar(object):
    def __init__(self):
        self._progressbar = None
        try:    
            import progressbar
        except ImportError as e:
            message.show('WARNING', '{}: {}'.format(type(e).__name__, str(e)))
        else:
            self._lib = progressbar
        self._silent = False

    def set_silent(self, state):
        self._silent = state
            
    def create(self, length):
        if not(self._silent):
            self._progressbar = self._lib.ProgressBar()
            self._progressbar.max_value = length
        
    def update(self, value):
        if not(self._silent):
            self._progressbar.update(value)
        
    def finish(self, dirty=False):
        if not(self._silent):
            self._progressbar.finish()


class XLoader(object):
    class Decorators(object):
        @classmethod
        def exit_on_exception(self, logger):
            def decorator(function):
                def wrapper(*args, **kwargs):
                    try:
                        result = function(*args, **kwargs)
                        if result is not None:
                            return result
                    except Exception as e:
                        logger.show('CRITICAL', '{}: {}, in module \'{}\''.format(type(e).__name__, str(e), \
                            function.__qualname__))
                        sys.exit(1)
                return wrapper
            return decorator

    def __init__(self):
        self.progress = ProgressBar()  
        self._IntelHex = None
        try:
            from intelhex import IntelHex
        except ImportError as e:
            message.show('WARNING', '{}: {}'.format(type(e).__name__, str(e)))
        else:
            self._IntelHex = IntelHex
        self.programmer = None
        self.i2c = {
            'bus': None, 
            'address': None
            }
        self.log = {
            'level': 'INFO'
            }
        self.arg = {
            'show_help': False,
            'silent_mode': False,
            'no_progress_indicator': False,
            'read_signature': False,
            'chip_erase': False,
            'get_sw_revision': False,
            'program_flash': False,
            'program_eeprom': False,
            'read_flash': False,
            'read_eeprom': False,
            'verify_flash': False,
            'verify_eeprom': False,
            'read_lock_bits': False,
            'read_fuse_bits': False,
            'device_name': '',
            'input_file_flash': '',
            'input_file_eeprom': '',
            'output_file_flash': '',
            'output_file_eeprom': '',
            'program_lock_bits': -1,
            'verify_lock_bits': -1
            }
        self._device_definition = 'devices.xml'
        self._flash_start = 0x0000
        self._flash_size = 0x0000
        self._flash_end = 0x0000
        self._eeprom_start = 0x0000
        self._eeprom_size = 0x0000
        self._eeprom_end = 0x0000
        self._block_support = False
        self._block_size  = 0x00
        self._auto_increment = False
        self._app_name = ''

    def usage(self, app_name):
        print('Command Line Switches:')
        print('    [-d device name] [--if infile] [--ie infile] [--of outfile] [--oe outfile]')
        print('    [-s] [-e] [--p[f|e|b]] [--r[f|e|b]] [--v[f|e|b]] [-l value] [-L value]')
        print('    [-y] [-q] [-b] [-g] [-z] [-h|?]')
        print('')
        print('Parameters:')
        print('-d     Device name. Must be applied when programming the device.')
        print('--if   Name of FLASH input file. Required for programming or verification')
        print('       of the FLASH memory. The file format is Intel Extended HEX.')
        print('--ie   Name of EEPROM input file. Required for programming or verification')
        print('       of the EEPROM memory. The file format is Intel Extended HEX.')
        print('--of   Name of FLASH output file. Required for readout of the FLASH memory.')
        print('       The file format is Intel Extended HEX.')
        print('--oe   Name of EEPROM output file. Required for readout of the EEPROM')
        print('       memory. The file format is Intel Extended HEX.')
        print('-s     Read signature bytes.')
        print('-e     Erase FLASH and EEPROM. If applied with another programming parameter,')
        print('       the memory will be erased before any other programming takes place.')
        print('--p    Program device; FLASH (f), EEPROM (e) or both (b). Corresponding')
        print('       input files are required.')
        print('--r    Read out device; FLASH (f), EEPROM (e) or both (b). Corresponding')
        print('       output files are required')
        print('--v    Verify device; FLASH (f), EEPROM (e) or both (b). Can be used with')
        print('       -p or alone. Corresponding input files are required.')
        print('-l     Set lock byte. "value" is an 8-bit hex. value.')
        print('-L     Verify lock byte. "value" is an 8-bit hex. value to verify against.')
        print('-y     Read back lock byte.')
        print('-q     Read back fuse bytes.')
        print('-b     Get software revision.')
        print('-g     Silent operation.')
        print('-z     No progress indicator. E.g. if piping to a file for log purposes.')
        print('-h|-?  Help information (overrides all other settings).')
        print('')
        print('Example:')
        print('       ', app_name, '-d ATxmega32E5 -if myapp.hex -vf')
        print('')
        
    def parse_command(self, argv):
        self._app_name = argv[0]
        try:
            optlist, args = getopt.getopt(argv[1:], 'bed:gh?l:L:qsyz', ['if=', 'ie=', 'of=', 'oe=', 'pf', 'pe', \
                'pb', 'rf', 're', 'rb', 'vf', 've', 'vb'])
        except getopt.GetoptError as e:
            message.show('CRITICAL', 'Can`t parse options, error({})'.format(e))
            self.usage(argv[0])
            sys.exit(1)
        for (x, y) in optlist:
            if x == '-b':
                self.arg['get_sw_revision'] = True
            elif x == '-d':
                self.arg['device_name'] = y
            elif x == '-e':
                self.arg['chip_erase'] = True
            elif x == '-g':
                self.arg['silent_mode'] = True
                self.arg['no_progress_indicator'] = True
            elif x == '-h' or x == '-?':
                self.arg['show_help'] = True
            elif x == '--if':
                self.arg['input_file_flash'] = y
            elif x == '--ie':
                self.arg['input_file_eeprom'] = y
            elif x == '-l':
                self.arg['program_lock_bits'] = self._safe_cast_hex_to_int(y)
            elif x == '-L':
                self.arg['verify_lock_bits'] = self._safe_cast_hex_to_int(y)
            elif x == '--of':
                self.arg['output_file_flash'] = y
            elif x == '--oe':
                self.arg['output_file_eeprom'] = y
            elif x == '--pf':
                self.arg['program_flash'] = True
            elif x == '--pe':
                self.arg['program_eeprom'] = True
            elif x == '--pb':
                self.arg['program_flash'] = True
                self.arg['program_eeprom'] = True
            elif x == '-q':
                self.arg['read_fuse_bits'] = True
            elif x == '--rf':
                self.arg['read_flash'] = True
            elif x == '--re':
                self.arg['read_eeprom'] = True
            elif x == '--rb':
                self.arg['read_flash'] = True
                self.arg['read_eeprom'] = True
            elif x == '-s':
                self.arg['read_signature'] = True
            elif x == '--vf':
                self.arg['verify_flash'] = True
            elif x == '--ve':
                self.arg['verify_eeprom'] = True
            elif x == '--vb':
                self.arg['verify_flash'] = True
                self.arg['verify_eeprom'] = True
            elif x == '-y':
                self.arg['read_lock_bits'] = True
            elif x == '-z':
                self.arg['no_progress_indicator'] = True
            else:
                self.usage(self._app_name)
                sys.exit(1)

    def exec_command(self):   
        if self.arg['show_help']:
            self.usage(self._app_name)
            return
        message.set_silent(self.arg['silent_mode'])
        self.progress.set_silent(self.arg['no_progress_indicator'])
        message.show('INFO', 'Using I2C bus \'{}\' at address 0x{}'.format(self.i2c['bus'], \
            self._byte_to_hex_string(self.i2c['address'])))
        if self.programmer is None:
            message.show('CRITICAL', 'First configure the programmer.') 
            sys.exit(1)
        self._enter_programming_mode(self.programmer) 
        self._check_auto_increment(self.programmer)       
        self._check_bootloader_version(self.programmer)
        self._check_block_support(self.programmer)
        signature = self._get_signature(self.programmer)
        device = AVRDevice()
        self._get_device_info(device, self._device_definition)
        # Check signature
        if signature != None:
            if signature.upper() != device.get_signature().upper():
                message.show('ERROR', 'Signature does not match device.')
                sys.exit(1)
        # Goto chip programing
        if self.arg['read_lock_bits']:
            self._read_lock_bits(self.programmer, device)
        if self.arg['read_fuse_bits']:
            self._read_fuse_bits(self.programmer, device)
        if self.arg['read_flash']:
            self._read_flash(self.programmer, device)
        if self.arg['read_eeprom']:
            self._read_eeprom(self.programmer, device)          
        if self.arg['chip_erase']:
            self._chip_erase(self.programmer, device)
        if self.arg['program_flash']:
            self._program_flash(self.programmer, device)
        if self.arg['program_eeprom']:
            self._program_eeprom(self.programmer, device)
        if not(self.arg['program_lock_bits'] is None):
            if self.arg['program_lock_bits'] >= 0:
                self._program_lock_bits(self.programmer, device)
        if not(self.arg['verify_lock_bits'] is None):
            if self.arg['verify_lock_bits'] >= 0:
                self._verify_lock_bits(self.programmer, device)
        if self.arg['verify_flash']:
            self._verify_flash(self.programmer, device)
        if self.arg['verify_eeprom']:
            self._verify_eeprom(self.programmer, device)
        # Finish
        self._leave_programming_mode(self.programmer)
        if self.programmer != None:
            self.programmer.close()
        
    def connect(self, programmer):
        self.programmer = programmer
  
    @Decorators.exit_on_exception(message)
    def _enter_programming_mode(self, programmer):
        # For XBoot bootloader it doesn't matter 
        programming_mode = programmer.enter_programming_mode() 
        if not(programming_mode['result']):
            message.show('CRITICAL', 'Set programming mode failed.')
            sys.exit(1)
        else:
            message.show('DEBUG', 'Set programming mode succeeded.')

    @Decorators.exit_on_exception(message)
    def _leave_programming_mode(self, programmer):
        # For XBoot bootloader it doesn't matter 
        programming_mode = programmer.leave_programming_mode()
        if not(programming_mode['result']):
            message.show('CRITICAL', 'Leaving programming mode failed.')
            
    @Decorators.exit_on_exception(message)
    def _check_auto_increment(self, programmer):
        auto = programmer.auto_increment_address()
        if (auto['result']) and (auto['code'] == XBootResponses.REPLY_YES.value):
            self._auto_increment = True
            message.show('DEBUG', 'Auto increment adress supported.')    
        else:
            message.show('WARNING', 'Auto increment adress not supported.')
            
    @Decorators.exit_on_exception(message)
    def _check_bootloader_version(self, prog):  
        if self.arg['get_sw_revision']:
            software = prog.return_software_identifier()
            version = prog.return_software_version()
            if software['result'] and version['result']:
                message.show('INFO', 'Bootloader: {} version: {}.'.format(software['data'], \
                    '.'.join([chr(version['major']), chr(version['minor'])])))
            else:
                message.show('CRITICAL', 'Error retrieving software revision.')
                sys.exit(1)
  
    @Decorators.exit_on_exception(message)
    def _get_signature(self, prog):               
        signature = None
        if self.arg['read_signature']:
            response = prog.read_signature_bytes()
            if response['result']:
                signature = self._list_to_hex_string(response['data'], True)
                message.show('INFO', 'Chip signature = 0x{}'.format(signature))
            else:
                message.show('CRITICAL', 'Error retrieving chip signature.')
                sys.exit(1)
        return signature
    
    @Decorators.exit_on_exception(message)
    def _check_block_support(self, prog):
        block_support = prog.check_block_support()
        if block_support['result']:
            if block_support['code'] == XBootResponses.REPLY_YES.value:
                self._block_support = True
                self._block_size = block_support['size']
                prog.set_maximum_block_size(self._block_size)
                message.show('DEBUG', 'Block mode is supported with block size: {} bytes'.format(self._block_size))
            else:
                message.show('DEBUG', 'Block mode is not supported')
        else:
            message.show('CRITICAL', 'Error retrieving block support.')
            sys.exit(1)
    
    @Decorators.exit_on_exception(message)
    def _get_device_info(self, device, file_name):
        if len(self.arg['device_name']) == 0:
            message.show('CRITICAL', 'Device name not specified.')
            sys.exit(1)
        if device.load_device_info(file_name, self.arg['device_name']):
            self._flash_size = device.get_flash_size()
            self._flash_end = self._flash_start + self._flash_size - 1
            self._eeprom_size = device.get_eeprom_size()
            self._eeprom_end = self._eeprom_start + self._eeprom_size - 1
        else:
            message.show('CRITICAL', 'Device name does not match any definition in \'{}\'.'.format(file_name))
            sys.exit(1)
  
    @Decorators.exit_on_exception(message)
    def _read_lock_bits(self, prog, device):
        response = prog.read_lock_bits()
        if response['result']:
            bits = self._byte_to_bin8_string(response['data'])
            byte = self._byte_to_hex_string(response['data'])
            message.show('INFO', 'Lock bits = 0b{} (0x{})'.format(bits, byte))
        else:
            message.show('CRITICAL', 'Lock bit read is not supported by this programmer.')
    
    @Decorators.exit_on_exception(message)
    def _verify_lock_bits(self, prog, device):
        message.show('INFO', 'Verifying lock bits...')
        response = prog.read_lock_bits()
        if response['result']:
            if response['data'] == self.arg['verify_lock_bits']:
                message.show('INFO', 'OK. Lock bits verified.')
            else:
                message.show('ERROR', 'Lock bits are different (0x{} vs 0x{})'.format( \
                    self._byte_to_hex_string(self.arg['verify_lock_bits']), \
                    self._byte_to_hex_string(response['data'])))
        else:
            message.show('CRITICAL', 'Lock bit read is not supported by this programmer.')

    @Decorators.exit_on_exception(message)
    def _program_lock_bits(self, prog, device):
        if self.arg['program_lock_bits'] >= 0:
            message.show('INFO', 'Programming lock bits...')
            response = prog.write_lock_bits(self.arg['program_lock_bits'])
            if response['result']:
                message.show('INFO', 'OK. Programming done.')
            else:
                message.show('INFO', 'Lock bit programming is not supported by this programmer.')

    @Decorators.exit_on_exception(message)
    def _read_fuse_bits(self, prog, device):
        if device.get_fuse_status():
            response = prog.read_low_fuse_bits()
            if response['result']:
                bits = self._byte_to_bin8_string(response['data'])
                byte = self._byte_to_hex_string(response['data'])
            message.show('INFO', 'Fuse low bits = 0b{} (0x{})'.format(bits, byte))
            response = prog.read_high_fuse_bits()
            if response['result']:
                bits = self._byte_to_bin8_string(response['data'])
                byte = self._byte_to_hex_string(response['data'])
            message.show('INFO', 'Fuse high bits = 0b{} (0x{})'.format(bits, byte))
        else: 
            message.show('INFO', 'Selected device has no fuse bits.')
        if device.get_ext_fuse_status():
            response = prog.read_extended_fuse_bits()
            if response['result']:
                bits = self._byte_to_bin8_string(response['data'])
                byte = self._byte_to_hex_string(response['data'])
            message.show('INFO', 'Fuse extended bits = 0b{} (0x{})'.format(bits, byte))
        else: 
            message.show('INFO', 'Selected device has no extended fuse bits.')

    @Decorators.exit_on_exception(message)
    def _read_flash(self, prog, device):
        errors = False
        if len(self.arg['output_file_flash']) == 0:
            message.show('INFO', 'Output file not specified.')
            return
        address = self._flash_start
        response = prog.set_address(self._flash_start)
        if not(response['result']):
            message.show('INFO', 'Flash address setting failed.')
            return
        message.show('INFO', 'Reading flash contents...')
        ih = self._IntelHex()
        self.progress.create(self._flash_size)
        if (self._block_support) and (self._block_size > 0x00): 
            while (address <= self._flash_end) and not(errors):
                self.progress.update(address)
                errors, address, size = self._preset_address(address, self._block_size, self._flash_end, prog, 'F')
                if not(errors):
                    bytes = prog.block_read('F', size)
                    if bytes['result']:
                        for i in range(size):
                            ih[address + i] = bytes['data'][i]
                        address += size
                    else:
                        errors = True
        else:
            while (address <= self._flash_end) and not(errors):
                self.progress.update(address)
                errors, address, size = self._preset_address(address, 2, self._flash_end, prog, 'F')
                if not(errors):
                    bytes = prog.read_program_memory()
                    if bytes['result']:
                        ih[address] = bytes['data'][1]
                        ih[address + 1] = bytes['data'][0]
                        address += 2
                    else:
                        errors = True        
        self.progress.finish(errors)
        self._check_reply_error(ih)
        if errors:
            message.show('CRITICAL', 'Read errors have occurred at address 0x{}, skipping to write to the Hex output file.'. \
                format(self._byte_to_hex_string(address, 3)))
        else:
            message.show('INFO', 'Writing to the Hex output file... ')
            self._write_intel_hex(ih, self.arg['output_file_flash'])

    @Decorators.exit_on_exception(message)
    def _verify_flash(self, prog, device):
        errors = False
        if len(self.arg['input_file_flash']) == 0:
            message.show('INFO', 'Cannot verify flash without a file specified.')
            return
        message.show('INFO', 'Reading hex input file...')
        ih = self._IntelHex()
        if self._load_intel_hex(ih, self.arg['input_file_flash']): 
            if (ih.minaddr() != 0x00) or (ih.maxaddr() != self._flash_end):
                message.show('INFO', 'Hex input files and flash has different size.')
                return
            differences = []
            address = self._flash_start
            response = prog.set_address(self._flash_start)
            if not(response['result']):
                message.show('INFO', 'Flash address setting failed.')
                return
            self.progress.create(self._flash_size)
            message.show('INFO', 'Comparing flash data...')
            if (self._block_support) and (self._block_size > 0x00):
                while (address <= self._flash_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, self._block_size, self._flash_end, prog, 'F')
                    if not(errors):
                        bytes = prog.block_read('F', size)
                        if bytes['result']:
                            for i in range(size):
                                byte_file = ih[address + i]
                                byte_flash = bytes['data'][i]
                                self._compare_bytes(address + i, byte_file, byte_flash, differences)
                            address += size
                        else:
                            errors = True                   
            else:
                while (address <= self._flash_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, 2, self._flash_end, prog, 'F')
                    if not(errors):
                        bytes = prog.read_program_memory()
                        if bytes['result']:
                            byte_hi_file = ih[address]
                            byte_hi_flash = bytes['data'][1]
                            self._compare_bytes(address, byte_hi_file, byte_hi_flash, differences)
                            byte_lo_file = ih[address + 1]
                            byte_lo_flash = bytes['data'][0]
                            self._compare_bytes(address + 1, byte_lo_file, byte_lo_flash, differences)
                            address += 2
                        else:
                            errors = True
            self.progress.finish(errors)
            if errors:
                message.show('CRITICAL', 'Read errors occurred at address 0x{}, verification skipped.'.format( \
                    self._byte_to_hex_string(address, 3)))
            else:
                if len(differences) > 0:
                    message.show('ERROR', 'Some errors occurred! Hex file and Flash are different.')
                    self._print_compare_errors(differences)
                else:
                    message.show('INFO', 'OK. Flash verified.')
                    
    @Decorators.exit_on_exception(message)
    def _program_flash(self, prog, device): 
        errors = False
        if len(self.arg['input_file_flash']) == 0:
            message.show('INFO', 'Cannot write flash without a file specified.')
            return
        message.show('INFO', 'Reading hex input file...')
        ih = self._IntelHex()
        if self._load_intel_hex(ih, self.arg['input_file_flash']): 
            if (ih.minaddr() != 0x00) or (ih.maxaddr() != self._flash_end):
                message.show('INFO', 'Hex input files and flash has different size.')
                return
            address = self._flash_start
            response = prog.set_address(self._flash_start)
            if not(response['result']):
                message.show('INFO', 'Flash address setting failed.')
                return
            self.progress.create(self._flash_size)
            message.show('INFO', 'Programming flash contents...')
            if (self._block_support) and (self._block_size > 0x00):
                while (address <= self._flash_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, self._block_size, self._flash_end, prog, 'F')
                    if not(errors):
                        to_write = []
                        for i in range(size):
                            to_write.append(ih[address + i])
                        bytes = prog.block_load('F', to_write)
                        if bytes['result']:
                            address += size
                        else:
                            errors = True     
            else:
                while (address <= self._flash_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, 2, self._flash_end, prog, 'F')
                    if not(errors):
                        bytes = prog.write_program_memory_low_byte(ih[address])
                        if bytes['result']:
                            bytes = prog.write_program_memory_high_byte(ih[address + 1])
                            if bytes['result']:
                                bytes = prog.issue_page_write()
                                if bytes['result']:
                                    address += 2
                                else:
                                    errors = True
                            else:
                                errors = True
                        else:
                            errors = True
            self.progress.finish(errors)
            if errors:
                message.show('CRITICAL', 'Write errors occurred at address 0x{}.'.format(self._byte_to_hex_string(address, 3))) 
            else:
                message.show('INFO', 'OK. Programing finished.')
                      
    @Decorators.exit_on_exception(message)
    def _read_eeprom(self, prog, device):
        errors = False
        if len(self.arg['output_file_eeprom']) == 0:
            message.show('INFO', 'Output file not specified.')
            return
        address = self._eeprom_start
        response = prog.set_address(self._eeprom_start)
        if not(response['result']):
            message.show('INFO', 'EEPROM address setting failed.')
            return
        message.show('INFO', 'Reading EEPROM contents...')
        ih = self._IntelHex()
        self.progress.create(self._eeprom_size)
        if (self._block_support) and (self._block_size > 0x00):
            while (address <= self._eeprom_end) and not(errors):
                self.progress.update(address)
                errors, address, size = self._preset_address(address, self._block_size, self._eeprom_end, prog, 'E')
                if not(errors):
                    bytes = prog.block_read('E', size)
                    if bytes['result']:
                        for i in range(size):
                            ih[address + i] = bytes['data'][i]
                        address += size
                    else:
                        errors = True
        else:
            while (address <= self._eeprom_end) and not(errors):
                self.progress.update(address)
                errors, address, size = self._preset_address(address, 1, self._eeprom_end, prog, 'E')
                if not(errors):
                    bytes = prog.read_data_memory()
                    if bytes['result']:
                        ih[address] = bytes['data']
                        address += 1
                    else:
                        errors = True
        self.progress.finish(errors)
        self._check_reply_error(ih)
        if errors:
            message.show('CRITICAL', 'Read errors have occurred at address 0x{}, skipping to write to the Hex output file.'. \
                format(self._byte_to_hex_string(address, 3)))
        else:
            message.show('INFO', 'Writing to the Hex output file... ')
            self._write_intel_hex(ih, self.arg['output_file_eeprom'])
 
    @Decorators.exit_on_exception(message)
    def _verify_eeprom(self, prog, device):
        errors = False
        if len(self.arg['input_file_eeprom']) == 0:
            message.show('INFO', 'Cannot verify flash without a file specified.')
            return
        message.show('INFO', 'Reading hex input file...')
        ih = self._IntelHex()
        if self._load_intel_hex(ih, self.arg['input_file_eeprom']): 
            if (ih.minaddr() != 0x00) or (ih.maxaddr() != self._eeprom_end):
                message.show('INFO', 'Hex input files and EEPORM has different size.')
                return
            differences = []
            address = self._eeprom_start
            response = prog.set_address(self._eeprom_start)
            if not(response['result']):
                message.show('INFO', 'EEPROM address setting failed.')
                return
            self.progress.create(self._eeprom_size)
            message.show('INFO', 'Comparing EEPROM data...')
            if (self._block_support) and (self._block_size > 0x00):
                while (address <= self._eeprom_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, self._block_size, self._eeprom_end, prog, 'E')
                    if not(errors):
                        bytes = prog.block_read('E', size)
                        if bytes['result']:
                            for i in range(size):
                                byte_file = ih[address + i]
                                byte_eeprom = bytes['data'][i]
                                self._compare_bytes(address + i, byte_file, byte_eeprom, differences)
                            address += size
                        else:
                            errors = True
            else:
                while (address <= self._eeprom_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, 1, self._eeprom_end, prog, 'E')
                    if not(errors):
                        bytes = prog.read_data_memory()
                        if bytes['result']:
                            byte_file = ih[address]
                            byte_eeprom = bytes['data']
                            self._compare_bytes(address, byte_file, byte_eeprom, differences)
                            address += 1
                        else:
                            errors = True
            self.progress.finish(errors)
            if errors:
                message.show('CRITICAL', 'Read errors occurred at address 0x{}, verification skipped.'.format( \
                    self._byte_to_hex_string(address, 3)))
            else:
                if len(differences) > 0:
                    message.show('ERROR', 'Some errors occurred! Hex file and EEPROM are different.')
                    self._print_compare_errors(differences)
                else:
                    message.show('INFO', 'OK. EEPROM verified.')

    @Decorators.exit_on_exception(message)
    def _program_eeprom(self, prog, device):
        errors = False
        if len(self.arg['input_file_eeprom']) == 0:
            message.show('INFO', 'Cannot write EEPROM without a file specified.')
            return
        message.show('INFO', 'Reading hex input file...')
        ih = self._IntelHex()
        if self._load_intel_hex(ih, self.arg['input_file_eeprom']): 
            if (ih.minaddr() != 0x00) or (ih.maxaddr() != self._eeprom_end):
                message.show('INFO', 'Hex input files and EEPORM has different size.')
                return
            address = self._eeprom_start
            response = prog.set_address(self._eeprom_start)
            if not(response['result']):
                message.show('INFO', 'EEPROM address setting failed.')
                return
            self.progress.create(self._eeprom_size)
            message.show('INFO', 'Programming EEPROM contents...')
            if (self._block_support) and (self._block_size > 0x00):
                while (address <= self._eeprom_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, self._block_size, self._eeprom_end, prog, 'E')
                    if not(errors):
                        to_write = []
                        for i in range(size):
                            to_write.append(ih[address + i])
                        bytes = prog.block_load('E', to_write)
                        if bytes['result']:
                            address += size
                        else:
                            errors = True
            else:
                while (address <= self._eeprom_end) and not(errors):
                    self.progress.update(address)
                    errors, address, size = self._preset_address(address, 1, self._eeprom_end, prog, 'E')
                    if not(errors):
                        bytes = prog.write_data_memory(ih[address])
                        if bytes['result']:
                            address += 1
                        else:
                            errors = True
            self.progress.finish(errors)
            if errors:
                message.show('CRITICAL', 'Write errors occurred at address 0x{}.'.format(self._byte_to_hex_string(address, 3)))                
            else:
                message.show('INFO', 'OK. Programing finished.')
            
    @Decorators.exit_on_exception(message)
    def _chip_erase(self, prog, device):
        if self.arg['chip_erase']:
            message.show('INFO', 'Erasing chip contents...')
            response = prog.chip_erase()
            if response['result']:
                message.show('INFO', 'OK. Erase completed.')
            else:
                message.show('INFO', 'Erasing is not supported by this programmer.')
                        
    def _compare_bytes(self, position, byte_file, byte_mem, diff):
        if (byte_file != byte_mem):
            diff.append([position, byte_file, byte_mem])
                                 
    def _check_reply_error(self, intelhex):
        result = True
        for i in range(intelhex.minaddr(), intelhex.maxaddr(), 1):
            if intelhex[i] != ord(XBootResponses.REPLY_ERROR.value):
                result = False
        if result:
            message.show('WARNING', 'While reading, the programmer cannot distinguish the data from the error code \'F3\'.')
            message.show('WARNING', 'Since all data are \'F3\', they are probably the result of an error during reading.')
        
    def _print_compare_errors(self, diff, length=20):
        length_half = int(length / 2)
        for i in diff[:length_half]:
            self._print_compare_message(i[0], i[1], i[2])
        if len(diff) > length:
            message.show('INFO', '.....')
        for i in diff[-(length - length_half):]:
            self._print_compare_message(i[0], i[1], i[2])
               
    def _print_compare_message(self, address, src, dst):
            message.show('INFO', 'Difference at {} (0x{} vs 0x{})'.format(self._byte_to_hex_string(address, 3), \
                self._byte_to_hex_string(src), self._byte_to_hex_string(dst)))
                                         
    def _load_intel_hex(self, ih, filename):
        result = True
        try:
            ih.fromfile(filename, format='hex')
        except Exception as e:
            message.show('WARNING', '{}: {}'.format(type(e).__name__, str(e)))
            result = False
        return result
                          
    def _write_intel_hex(self, ih, filename):
        result = True
        try:
            ih.write_hex_file(filename)
        except Exception as e:
            message.show('WARNING', '{}: {}'.format(type(e).__name__, str(e)))
            result = False
        return result
    
    def _byte_to_bin8_string(self, data, bytes=1):
        return ''.join(['0' * 8 * bytes, format(data, 'b')])[(-8 * bytes):]

    def _byte_to_hex_string(self, data, bytes=1):
        return ''.join(['00' * bytes, format(data, 'x')])[(-2 * bytes):].upper()
        
    def _list_to_hex_string(self, data, reverse_order=False):
        result = []
        for i in data:
            temp = ''.join(['00', format(i, 'x')])
            if reverse_order:
                result.insert(0, temp[-2:])
            else:
                result.append(temp[-2:])
        return ''.join(result).upper()

    def _safe_cast_hex_to_int(self, val, default=None):
        try:
            return int(val, 16)
        except (ValueError, TypeError):
            return default

    @Decorators.exit_on_exception(message)
    def _preset_address(self, address, size, end, programmer, type):
        errors = False
        if not(self._auto_increment):
            if type == 'F':
                response = programmer.set_address(address >> 1)
            elif type == 'E':
                response = programmer.set_address(address)
            else:
                response = programmer.set_address(address)
            errors = not(response['result'])
        if (end + 1 - address) < size:
            size = end + 1 - address
        return (errors, address, size)
                                    
class Configurator(object):
    def __init__(self, attributes=None):
        self._attributes = attributes
        self._search_list = ['yaml']
        self._validator = {}

    def set_validator(self, validator):
        self._validator = validator
        
    def set_destination(self, attributes):
        self._attributes = attributes

    def from_file(self, config_file_name=None):
        import yaml
        if config_file_name is None:
            file_name = __file__
            if file_name[-3:] == '.py':
                file_name = file_name[:-3]
                for i in self._search_list:
                    if os.path.isfile('.'.join([file_name, i])):
                        config_file_name = '.'.join([file_name, i])
                        break
        if config_file_name is None:
            raise ValueError('The configuration file name has not been resolved')
        if os.path.isfile(config_file_name):
            cfg = {}
            with open(config_file_name, 'r') as yamlfile:
                cfg = yaml.safe_load(yamlfile)
            self._update(cfg, self._validator, self._attributes)
        else:
            raise FileNotFoundError 
        
    def _update(self, source, validator, destination):
        if not(destination is None):
            dicts_to_process = [(source, validator, destination)]       
            while dicts_to_process:
                src, valid, dst = dicts_to_process.pop()
                for key in src.keys():
                    if key in valid:              
                        if type(src[key])== dict:
                            if type(valid[key])== dict:
                                if key not in dst:
                                    dst[key] = {}
                                if type(dst[key])!= dict:
                                    dst[key] = {}
                                dicts_to_process.append((src[key], valid[key], dst[key]))
                        elif type(src[key]) in valid[key]:
                            dst[key] = src[key]
           
class AVRDevice(object):
    """
    This is a class representing the properties of the AVR device. 
    
    XML schema of the source file
    <?xml version="1.0" encoding="UTF-8"?>
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" elementFormDefault="qualified">
      <xs:element name="xloader">
        <xs:complexType>
          <xs:sequence>
            <xs:element ref="devices"/>
          </xs:sequence>
        </xs:complexType>
      </xs:element>
      <xs:element name="devices">
        <xs:complexType>
          <xs:sequence>
            <xs:element maxOccurs="unbounded" ref="device"/>
          </xs:sequence>
        </xs:complexType>
      </xs:element>
      <xs:element name="device">
        <xs:complexType>
          <xs:sequence>
            <xs:element ref="flash_size"/>
            <xs:element ref="eeprom_size"/>
            <xs:element ref="fuse_bits"/>
            <xs:element ref="ext_fuse_bits"/>
            <xs:element ref="signature"/>
          </xs:sequence>
          <xs:attribute name="name" use="required" type="xs:NCName"/>
        </xs:complexType>
      </xs:element>
      <xs:element name="flash_size" type="xs:NMTOKEN"/>
      <xs:element name="eeprom_size" type="xs:NMTOKEN"/>
      <xs:element name="fuse_bits" type="xs:NCName"/>
      <xs:element name="ext_fuse_bits" type="xs:NCName"/>
      <xs:element name="signature" type="xs:NMTOKEN"/>
    </xs:schema>
    """ 
    def __init__(self):
        self._device_name = ''
        self._flash_size = 0x00
        self._eeprom_size = 0x00
        self._has_fuse_bits = False
        self._has_extended_fuse_bits = False
        self._signature = ''

    def load_device_info(self, filename, name):
        import xml.etree.ElementTree as et
        if len(name) == 0:
            return False
        found = False
        xml_root = et.parse(filename).getroot()  
        if xml_root != None: 
            for device in xml_root.findall('devices/device'):
                self._device_name = device.get('name')
                if self._device_name.lower() == name.lower():
                    self._flash_size = int(device.find('flash_size').text, 0)
                    self._eeprom_size = int(device.find('eeprom_size').text, 0)
                    self._has_fuse_bits = self._str2bool(device.find('fuse_bits').text)
                    self._has_extended_fuse_bits = self._str2bool(device.find('ext_fuse_bits').text)
                    self._signature = device.find('signature').text
                    found = True
                    break
        return found
        
    def get_device_name(self):
        return self._device_name

    def get_flash_size(self):
        return self._flash_size

    def get_eeprom_size(self):
        return self._eeprom_size

    def get_fuse_status(self):
        return self._has_fuse_bits

    def get_ext_fuse_status(self):
        return self._has_extended_fuse_bits

    def get_signature(self):
        return self._signature
     
    def _str2bool(self, v):
        return v.lower() in ("yes", "true", "t", "1")
                
class XBootMemoryTypes(Enum):
    """
    From XBoot protocol.h
    """
    MEM_EEPROM = 'E'
    MEM_FLASH = 'F'
    MEM_USERSIG = 'U'
    MEM_PRODSIG = 'P' 
    
class XBootCRC(Enum):
    """
    From XBoot protocol.h
    """
    SECTION_FLASH = 'F'
    SECTION_APPLICATION = 'A'
    SECTION_BOOT = 'B'
    SECTION_APP = 'a'
    SECTION_APP_TEMP = 't' 
        
class XBootResponses(Enum):
    """
    From XBoot protocol.h
    """
    REPLY_ACK = '\r'  
    REPLY_YES = 'Y'
    REPLY_ERROR = '?'
   
class XBoot(object):
    """
    XBoot class.
    The class representing the XBoot bootloader (Atmel AVR109 with some XBoot extensions).
    http://alexforencich.com/wiki/en/xboot/ 
    https://github.com/alexforencich/xboot 
    """
    def __init__(self, bus):
        self._bus = bus
        self._block_size_max = 0
        self._crc_delay = 0.5
        self._software_id_length = 7
        self._supported_devices_length_max = 256
    
    def set_maximum_block_size(self, size):
        self._block_size_max = size

    def get_maximum_block_size(self):
        return self._block_size_max
        
    def close(self):
        self._bus.close()
    
    # Informational Commands 
    def auto_increment_address(self):
        """
        Checks for auto increment address support. 

        :return: Result status
        :rtype: dict[Boolean, str]
        """
        result = True
        self._bus.write([ord('a')])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']):
            result = False
        return {'result': result, 'code': response['code']}
        
    def check_block_support(self):
        """
        Checks support for block operations and get block size. 

        :return: Result status, block handling code and supported block size
        :rtype: dict[Boolean, str, int]
        """ 
        result = True
        self._bus.write([ord('b')])
        data = self._bus.read(3)
        response = self._list_to_block_support(data)
        if not(response['result']):
            result = False
        return {'result': result, 'code': response['code'], 'size': response['size']}
        
    def return_programmer_type(self):
        """
        Reads programmer type. 

        :return: Result status and programmer type
        :rtype: dict[Boolean, int]
        """
        result = True
        self._bus.write([ord('p')])
        data = self._bus.read()
        return {'result': result, 'data': data[0]}
        
    def return_supported_device_codes(self):
        """
        Reads a list of supported devices. 

        :return: Result status and list of supported devices
        :rtype: dict[Boolean, list[int]]
        """
        result = True
        self._bus.write([ord('t')])
        data = []
        code = self._bus.read()
        while (code[0] != 0x00) and (len(data) < self._supported_devices_length_max):
            data.extend(code)
            code = self._bus.read()
            # for support XBoot I2C read, byte by byte
            if code[0] == 0xff:
                break
        if len(data) == self._supported_devices_length_max:
            result = False
        return {'result': result, 'data': data}
    
    def return_software_identifier(self):
        """
        Reads a software identifier. 

        :return: Result status and software identifier
        :rtype: dict[Boolean, str]
        """
        result = True
        self._bus.write([ord('S')])
        data = self._bus.read(self._software_id_length)
        return {'result': result, 'data': self._list_to_string(data)}
    
    def return_software_version(self):
        """
        Reads a software version. 

        :return: Result status and software version
        :rtype: dict[Boolean, int, int]
        """
        result = True
        self._bus.write([ord('V')])
        items = 2
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data)))) 
        return {'result': result, 'major': data[0], 'minor': data[1]}

    def read_signature_bytes(self):
        """
        Reads a chip signature bytes. 

        :return: Result status and chip signature bytes
        :rtype: dict[Boolean, list[int]]
        """
        result = True
        self._bus.write([ord('s')])
        items = 3
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data)))) 
        return {'result': result, 'data': data}
        
    # Addressing 
    def set_address(self, address):
        """
        Sets address. 

        :param address: Address to set
        :type address: int
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if address > 0xffff:
            raise ValueError('The address ({}) is out of range'.format(address))
        addres_list = [ord('A')]
        addres_list.append((address >> 8) & 0xff)
        addres_list.append(address & 0xff)
        self._bus.write(addres_list)
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
    
    def set_extended_address(self, address):
        """
        Sets extended address. 

        :param address: Address to set
        :type address: int
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if address > 0xffffff:
            raise ValueError('The address ({}) is out of range'.format(address))
        addres_list = [ord('H')]
        addres_list.append((address >> 16) & 0xff)
        addres_list.append((address >> 8) & 0xff)
        addres_list.append(address & 0xff)
        self._bus.write(addres_list)
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}

    # Erase
    def chip_erase(self):
        """
        Chip erase. 

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        self._bus.write([ord('e')])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
    
    # Block Access
    def block_read(self, type, block_size):
        """
        Reads a memory block. 

        :param type: Memory type
        :type type: str
        :param block_size: Memory block size
        :type block_size: int
        :return: Result status and contents of the memory block
        :rtype: dict[Boolean]
        """
        result = True
        data = []
        if block_size > self._block_size_max:
            raise ValueError('Unsupported block size')
        if not(self._is_memory_type(type)):
            raise ValueError('Unsupported memory type')
        to_write = [ord('g')]
        to_write.append((block_size >> 8) & 0xff)
        to_write.append(block_size & 0xff)
        to_write.append(ord(type))
        self._bus.write(to_write)
        data = self._bus.read(block_size)
        if len(data) != block_size:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(block_size, str(len(data)))) 
        return {'result': result, 'data': data}
    
    def block_load(self, type, block):
        """
        Writes a block of data to memory. 

        :param type: Memory type
        :type type: str
        :param block: Data to be saved in memory
        :type block: list 
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        block_size = len(block)
        if block_size > self._block_size_max:
            raise ValueError('The data length exceeds the supported block size')
        if not(self._is_memory_type(type)):
            raise ValueError('Unsupported memory type')
        for i in block:
            if not(self._is_byte_value(i)):
                raise ValueError('({}) is not a byte value'.format(i))
        block.insert(0, ord(type))
        block.insert(0, block_size & 0xff)
        block.insert(0, (block_size >> 8) & 0xff)
        block.insert(0, ord('B'))
        self._bus.write(block)
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
        
    # Byte Access 
    def read_program_memory(self):
        """
        Reads two bytes of program memory. 

        :return: Result status and memory content
        :rtype: dict[Boolean, list[int]]
        """
        result = True
        self._bus.write([ord('R')])
        items = 2
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data)))) 
        return {'result': result, 'data': data}
        
    def write_program_memory_low_byte(self, byte_value):
        """
        Write low byte to buffer. 

        :param byte_value: Data to be saved in memory
        :type byte_value: int 
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if not(self._is_byte_value(byte_value)):
            raise ValueError('({}) is not a byte value'.format(byte_value))
        self._bus.write([ord('c'), byte_value])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
        
    def write_program_memory_high_byte(self, byte_value):
        """
        Write high byte to buffer.

        :param byte_value: Data to be saved in memory
        :type byte_value: byte 
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if not(self._is_byte_value(byte_value)):
            raise ValueError('({}) is not a byte value'.format(byte_value))
        self._bus.write([ord('C'), byte_value])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
        
    def issue_page_write(self):
        """
        Rrite buffer bytes to memory.

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        self._bus.write([ord('m')])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
        
    def write_data_memory(self, byte_value):
        """
        Write a byte to EEPROM. 

        :param byte_value: Data to be saved in memory
        :type byte_value: byte 
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if not(self._is_byte_value(byte_value)):
            raise ValueError('({}) is not a byte value'.format(byte_value))
        self._bus.write([ord('D'), byte_value])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
        
    def read_data_memory(self):
        """
        Reads byte of EEPROM. 

        :return: Result status and memory content
        :rtype: dict[Boolean, int]
        """
        result = True
        self._bus.write([ord('d')])
        items = 1
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data))))
        return {'result': result, 'data': data[0]}
    
    # Lock and Fuse Bits 
    def write_lock_bits(self, byte_value):
        """
        Write a lock bits. 

        :param byte_value: Data to be saved
        :type byte_value: byte 
        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if not(self._is_byte_value(byte_value)):
            raise ValueError('({}) is not a byte value'.format(byte_value))
        self._bus.write([ord('l'), byte_value])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
    
    def read_lock_bits(self):
        """
        Reads a lock bits. 

        :return: Result status and lock bits
        :rtype: dict[Boolean, int]
        """
        result = True
        self._bus.write([ord('r')])
        items = 1
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data))))
        return {'result': result, 'data': data[0]}

    def read_low_fuse_bits(self):
        """
        Reads a low fuse bits. 

        :return: Result status and low fuse bits
        :rtype: dict[Boolean, int]
        """
        result = True
        self._bus.write([ord('F')])
        items = 1
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data))))
        return {'result': result, 'data': data[0]}

    def read_high_fuse_bits(self):
        """
        Reads a high fuse bits. 

        :return: Result status and high fuse bits
        :rtype: dict[Boolean, int]
        """
        result = True
        self._bus.write([ord('N')])
        items = 1
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data))))
        return {'result': result, 'data': data[0]}
        
    def read_extended_fuse_bits(self):
        """
        Reads a extended fuse bits. 

        :return: Result status and extended fuse bits
        :rtype: dict[Boolean, int]
        """
        result = True
        self._bus.write([ord('Q')])
        items = 1
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data))))
        return {'result': result, 'data': data[0]}
        
    # Bootloader Commands 
    def enter_programming_mode(self):
        """
        Enter programming mode. 

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        self._bus.write([ord('P')])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
        
    def leave_programming_mode(self):
        """
        Leave programming mode. 

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        self._bus.write([ord('L')])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
      
    def exit_bootloader(self):
        """
        Exits the bootloader. 

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        self._bus.write([ord('E')])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
    
    def set_led(self, byte_value):
        """
        Turn on the LED. 

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if not(self._is_byte_value(byte_value)):
            raise ValueError('({}) is not a byte value'.format(byte_value))
        self._bus.write([ord('x'), byte_value])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}

    def clear_led(self, byte_value):
        """
        Turn off the LED. 

        :return: Result status
        :rtype: dict[Boolean]
        """
        result = True
        if not(self._is_byte_value(byte_value)):
            raise ValueError('({}) is not a byte value'.format(byte_value))
        self._bus.write([ord('y'), byte_value])
        data = self._bus.read()
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_ACK.value):
            result = False
        return {'result': result}
    
    def crc(self, section):
        """
        Obtains the CRC16 value of the memory section. 

        :return: Result status and CRC value
        :rtype: dict[Boolean, list[int]]
        """
        result = True
        if not(self._is_crc_section(section)):
            raise ValueError('Unsupported CRC section type')
        self._bus.write([ord('h'), ord(section)])
        time.sleep(self._crc_delay)
        items = 2
        data = self._bus.read(items)
        if len(data) != items:
            raise ValueError('Invalid data length, {} item(s) expected, {} received'.format(items, str(len(data)))) 
        return {'result': result, 'data': data}
       
    def _is_memory_type(self, type):
        """
        Checks if the string is a valid memory type code.

        :param type: Type code to check
        :type type: str
        :return: Check result
        :rtype: Boolean
        """ 
        if type in {XBootMemoryTypes.MEM_FLASH.value, XBootMemoryTypes.MEM_EEPROM.value, \
            XBootMemoryTypes.MEM_USERSIG.value, XBootMemoryTypes.MEM_PRODSIG.value}:
            return True
        else:
            return False

    def _is_crc_section(self, type):
        """
        Checks if the string is a valid section type code.

        :param type: Type code to check
        :type type: str
        :return: Check result
        :rtype: Boolean
        """ 
        if type in {XBootCRC.SECTION_FLASH.value, XBootCRC.SECTION_APPLICATION.value, XBootCRC.SECTION_BOOT.value, \
            XBootCRC.SECTION_APP.value, XBootCRC.SECTION_APP_TEMP.value}:
            return True
        else:
            return False
            
    def _is_byte_value(self, value):  
        result = False
        if isinstance(value, int):
            if (value >= 0) and (value < 256):    
                result = True
        return result
    
    def _list_to_string(self, data):
        """
        Convert the list of character codes into a string.

        :param data: Data to convert
        :type data: list
        :return: Converted string
        :rtype: str
        """ 
        return ''.join(chr(i) for i in data)
     
    def _list_to_block_support(self, data):
        """
        Return support for block operations and block size. 

        :param data: Data to convert
        :type data: list
        :return: Result, support and block size
        :rtype: dict
        """ 
        result = True
        if len(data) != 3:
            raise ValueError('Incorect data length, expected 3 items, got {}'.format(str(len(data)))) 
        response = self._byte_to_response(data[0])
        if not(response['result']) or not(response['code'] == XBootResponses.REPLY_YES.value):
            result =False
        size = (data[1] << 8) + data[2]
        return {'result': result, 'code': response['code'], 'size': size}
    
    def _byte_to_response(self, data):
        """
        Returns byte as XBoot command response code. 

        :param data: Byte to conver
        :type data: int
        :return: Result and response code
        :rtype: dict
        """ 
        result = True
        code = chr(data)
        if not(code in [XBootResponses.REPLY_ACK.value, XBootResponses.REPLY_YES.value, \
            XBootResponses.REPLY_ERROR.value]):
            result = False
        return {'result': result, 'code': code}
       
class PiBusI2C(object):
    """
    Class of basic I2C communication commands based on SMBus2
    https://pypi.org/project/smbus2/
    https://github.com/kplindegaard/smbus2
    """
    
    def __init__(self, bus, address):
        """
        Initialize an I2C bus connection.

        :param bus: I2C bus number (e.g. 0 or 1)
            or an absolute file path (e.g. `/dev/i2c-1`).
        :type bus: int or str
        :param address: 7 bit device address.
        :type address: int
        """ 
        if (bus is None) or (address is None):
            raise ValueError('I2C \'bus\' or \'address\' has no value.') 
        import smbus2     
        self._smbus = smbus2.SMBus(bus)
        self._msg = smbus2.i2c_msg
        self._address = address
                
    def close(self):
        """
        Close the I2C connection.
        """ 
        self._smbus.close()
               
    def read(self, size=1):
        """
        Reads (size) bytes from the bus.

        :param size: Desired block size
        :type size: int
        :return: Received bytes
        :rtype: list
        """         
        receiver = self._msg.read(self._address, size)
        self._smbus.i2c_rdwr(receiver)
        return list(receiver)

    def write(self, data):
        """
        Write bytes (data) to the bus.

        :param data: Bytes to send
        :type data: list
        """ 
        to_write = self._msg.write(self._address, data)
        self._smbus.i2c_rdwr(to_write)

        
if __name__ == '__main__':
    programmer = XLoader()
    setup = Configurator()
    setup.set_destination(programmer.__dict__)
    validator = {
        'log': {'level': [str]},
        'i2c': {'bus': [int, str], 'address': [int]},
        'arg': {
            'show_help': [bool],
            'silent_mode': [bool],
            'no_progress_indicator': [bool],
            'read_signature': [bool],
            'chip_erase': [bool],
            'get_sw_revision': [bool],
            'program_flash': [bool],
            'program_eeprom': [bool],
            'read_flash': [bool],
            'read_eeprom': [bool],
            'verify_flash': [bool],
            'verify_eeprom': [bool],
            'read_lock_bits': [bool],
            'read_fuse_bits': [bool],
            'device_name': [str],
            'input_file_flash': [str],
            'input_file_eeprom': [str],
            'output_file_flash': [str],
            'output_file_eeprom': [str],
            'program_lock_bits': [str],
            'verify_lock_bits': [str]
        }
    }
    setup.set_validator(validator)
    try:
        setup.from_file()
    except Exception as e:
        message.show('WARNING', '{}: {}'.format(type(e).__name__, str(e)))
    message.set_level(programmer.log['level'])
    try:
        programmer.connect(XBoot(PiBusI2C(programmer.i2c['bus'], programmer.i2c['address'])))
    except Exception as e:
        message.show('WARNING', '{}: {}'.format(type(e).__name__, str(e)))
        sys.exit(1)
    programmer.parse_command(sys.argv)
    programmer.exec_command()
    sys.exit(0)

    