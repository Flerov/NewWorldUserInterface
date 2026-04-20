#pragma once

#define MAPPING_NAME_INPUT  L"\\BaseNamedObjects\\MySharedMemory"
#define MAPPING_NAME_OUTPUT L"\\BaseNamedObjects\\VADSharedMemory"
#define MAPPING_NAME_FROM_FILENAMES L"\\BaseNamedObjects\\VADSharedMemoryFileNames"
#define MAPPING_NAME_WRITE_PHYS L"\\BaseNamedObjects\\WritePhysicalMemory"
#define MAPPING_NAME_READ_PHYS L"\\BaseNamedObjects\\ReadPhysicalMemory"
#define MAPPING_NOTIFICATION_LINK_EVENT L"\\BaseNamedObjects\\Global\\LinkMemory"
#define MAPPING_NOTIFICATION_Unlink_EVENT L"\\BaseNamedObjects\\Global\\UnlinkMemory"
#define MAPPING_NOTIFICATION_INIT_EVENT L"\\BaseNamedObjects\\Global\\InitializeMemory"
#define MAPPING_NOTIFICATION_USERMODEREADY_EVENT L"\\BaseNamedObjects\\Global\\UserModeReadEvent"
#define MAPPING_NOTIFICATION_WRITE_PHYS_EVENT L"\\BaseNamedObjects\\Global\\WritePhysicalMemoryEvent"
#define MAPPING_NOTIFICATION_READ_PHYS_EVENT L"\\BaseNamedObjects\\Global\\ReadPhysicalMemoryEvent"
#define MAPPING_NAME_VAD_MODIFY              L"\\BaseNamedObjects\\VADModifyRequest"
#define MAPPING_NOTIFICATION_VAD_INSERT_EVENT L"\\BaseNamedObjects\\Global\\VADInsertEvent"
#define MAPPING_NOTIFICATION_VAD_REMOVE_EVENT L"\\BaseNamedObjects\\Global\\VADRemoveEvent"

#define MAX_FILENAME_SIZE 80
#define MAX_WRITE_BUFFER_SIZE 4096
#define MAX_READ_BUFFER_SIZE 4096
#define FILE_DEVICE_NW_INTERFACE 0x9000

// -----------------------------------------------------------------
#define BYTE_               sizeof (BYTE)
#define WORD_               sizeof (WORD)
#define DWORD_              sizeof (DWORD)
#define QWORD_              sizeof (QWORD)
#define BOOL_               sizeof (BOOL)
#define PVOID_              sizeof (PVOID)
#define HANDLE_             sizeof (HANDLE)
#define PHYSICAL_ADDRESS_   sizeof (PHYSICAL_ADDRESS)
// -----------------------------------------------------------------
#define DRV_MODULE          NewWorldInterface
#define DRV_NAME            NW Windows 2025 _INTERACE
#define DRV_COMPANY         Me
#define DRV_AUTHOR          Me
#define DRV_EMAIL           me@me.me
#define DRV_PREFIX          NW
// -----------------------------------------------------------------
#define _DRV_DEVICE(_name)  \\Device\\     ## _name
#define _DRV_LINK(_name)    \\DosDevices\\ ## _name
#define _DRV_PATH(_name)    \\\\.\\        ## _name
// -----------------------------------------------------------------
#define DRV_DEVICE              _DRV_DEVICE (DRV_MODULE)
#define DRV_LINK                _DRV_LINK   (DRV_MODULE)
#define DRV_PATH                _DRV_PATH   (DRV_MODULE)
#define DRV_EXTENSION           sys
// -----------------------------------------------------------------
#define _CSTRING(_text) #_text
#define CSTRING(_text) _CSTRING (_text)
// -----------------------------------------------------------------
#define _USTRING(_text) L##_text
#define USTRING(_text) _USTRING (_text)
// -----------------------------------------------------------------
#define PRESET_UNICODE_STRING(_symbol,_buffer) \
        UNICODE_STRING _symbol = \
            { \
            sizeof (USTRING (_buffer)) - sizeof (WORD), \
            sizeof (USTRING (_buffer)), \
            USTRING (_buffer) \
            };