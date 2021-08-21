# Python driver walkthrough


- Open device `open()` in init.py
  - open usb `usb.open()` in usb.py
  	- find device
	- open device
  - initilize the flash of the device `init_flash()` in init_flash.py
    - get flash info `get_flash_info()` in flash.py
	  - send usb message `0x3e` (using `tls` but before a secure con established so its not encrypted?)
	  - check response status ok
	  - first 2 bytes are status
	  - read flash_info from response
    - if the flash is partitioned we are done
	- otherwise need to format
	  - send reset_blob
	  - generate private and public keys
	  - `partition_flash()` in init_flash.py
	    - TODO: this part

  - send usb initilization `usb.send_init()` in usb.py
    - send `0x01` (something to do with hardware?)
	- send `0x19` (something to do with hardware?)
	- send hardcoded init message (is this always the same?)
	- if the status is not 0 fwext is not loaded (fwext is firmware for device?)
	  - send clean slate init message

  - read tls from flash `read_tls_flash()` in flash.py
    - read_flash(1, 0, 0x1000)
	  - send packet to usb through tls (not encrypted?)
	    - byte 0x41 (flash read command?)
	    - byte 1 (parition index)
		- byte 1 (?)
		- word 0 (?)
		- dowrd 0 (start address in flash?)
		- dword 0x1000 (size of read?)
		- 
	  - third byte in response is size
	  - response[ 8:8 + size ] is tls_flash data
  - parse tls flash data `parse_tls_flash` in tls.py
    - parse blocks of data from flash data
	  - TODO

  - start tls session with data from last step

  - upload firmware `upload_fwext()` in upload_fwext.py
    - if theres alread firmware skip this
	- TODO


  - open sensor

  - initilize database
	

	
  