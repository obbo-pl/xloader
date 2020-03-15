# xloader

It is a command-line tool using the same syntax as Atmel AVROSP application. Currently, it is compatible with the AVR109 bootloader protocol and XBoot bootloader (https://github.com/alexforencich/xboot). Unlike AVROSP, it does not require installing AVR Studio. Currently only includes support for the I2C Raspberry Pi bus.

### Installation:
```
sudo apt-get install python3-pip python3-yaml
sudo python3 -m pip install smbus intelhex progressbar2
```
Copy and unzip files:
```
cd /usr/local/
sudo wget https://github.com/obbo-pl/xloader/archive/master.zip
sudo unzip master.zip
```
go to the directory and add execute permission to *.py files
```
cd /usr/local/xloader-master
sudo chmod a+x *.py
```
just run:
```
./xloader.py -?
Command Line Switches:
    [-d device name] [--if infile] [--ie infile] [--of outfile] [--oe outfile]
    [-s] [-e] [--p[f|e|b]] [--r[f|e|b]] [--v[f|e|b]] [-l value] [-L value]
    [-y] [-q] [-b] [-g] [-z] [-h|?]

Parameters:
-d     Device name. Must be applied when programming the device.
--if   Name of FLASH input file. Required for programming or verification
       of the FLASH memory. The file format is Intel Extended HEX.
--ie   Name of EEPROM input file. Required for programming or verification
       of the EEPROM memory. The file format is Intel Extended HEX.
--of   Name of FLASH output file. Required for readout of the FLASH memory.
       The file format is Intel Extended HEX.
--oe   Name of EEPROM output file. Required for readout of the EEPROM
       memory. The file format is Intel Extended HEX.
-s     Read signature bytes.
-e     Erase FLASH and EEPROM. If applied with another programming parameter,
       the memory will be erased before any other programming takes place.
--p    Program device; FLASH (f), EEPROM (e) or both (b). Corresponding
       input files are required.
--r    Read out device; FLASH (f), EEPROM (e) or both (b). Corresponding
       output files are required
--v    Verify device; FLASH (f), EEPROM (e) or both (b). Can be used with
       -p or alone. Corresponding input files are required.
-l     Set lock byte. "value" is an 8-bit hex. value.
-L     Verify lock byte. "value" is an 8-bit hex. value to verify against.
-y     Read back lock byte.
-q     Read back fuse bytes.
-b     Get software revision.
-g     Silent operation.
-z     No progress indicator. E.g. if piping to a file for log purposes.
-h|-?  Help information (overrides all other settings).

Example:
        ./xloader.py -d ATxmega32E5 -if myapp.hex -vf
```
Example of use:
```
pi@raspberrypi:/usr/local/xloader $ ./xloader.py -d atxmega32e5 -s -y --if 'flash.hex' --pf --vf -q
Using I2C bus '/dev/i2c-1' at address 0x2A
Bootloader: XBoot++ version: 1.7.
Chip signature = 0x1E954C
Lock bits = 0b11111111 (0xFF)
Fuse low bits = 0b11111111 (0xFF)
Fuse high bits = 0b11111111 (0xFF)
Fuse extended bits = 0b10111111 (0xBF)
Reading hex input file...
Programming flash contents...
100% (32768 of 32768) |############################################| Elapsed Time: 0:00:09 Time:  0:00:09
OK. Programing finished.
Reading hex input file...
Comparing flash data...
100% (32768 of 32768) |############################################| Elapsed Time: 0:00:08 Time:  0:00:08
OK. Flash verified.
```
Instead, you can use the modules contained in the script
```
pi@raspberrypi:/usr/local/xloader $ python3
Python 3.5.3 (default, Sep 27 2018, 17:25:39)
[GCC 6.3.0 20170516] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import xloader
>>> loader = xloader.XBoot(xloader.PiBusI2C(1, 0x2A))
>>> loader.return_software_identifier()
{'data': 'XBoot++', 'result': True}
>>> loader.check_block_support()
{'size': 128, 'result': True, 'code': 'Y'}
>>>
```
