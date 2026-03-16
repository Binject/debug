package pe

import (
	"bytes"
	"encoding/binary"
)

// from https://github.com/google/syzygy/blob/master/syzygy/pe/pe_structs.h#L27
type IMAGE_LOAD_CONFIG_CODE_INTEGRITY struct {
	Flags,
	Catalog uint16
	CatalogOffset,
	Reserved uint32
}

// Contains the load configuration data of an image. https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
type IMAGE_LOAD_CONFIG_DIRECTORY struct {
	Size                          uint32 //The size of the structure. For Windows XP, the size must be specified as 64 for x86 images.
	TimeDateStamp                 uint32 //The date and time stamp value. The value is represented in the number of seconds elapsed since midnight (00:00:00), January 1, 1970, Universal Coordinated Time, according to the system clock. The time stamp can be printed using the C run-time (CRT) function ctime.
	MajorVersion                  uint16 //The major version number.
	MinorVersion                  uint16 //The minor version number.
	GlobalFlagsClear              uint32 //The global flags that control system behavior. For more information, see Gflags.exe.
	GlobalFlagsSet                uint32 //The global flags that control system behavior. For more information, see Gflags.exe.
	CriticalSectionDefaultTimeout uint32 //The critical section default time-out value.
	DeCommitFreeBlockThreshold    uint32 //The size of the minimum block that must be freed before it is freed (de-committed), in bytes. This value is advisory.
	DeCommitTotalFreeThreshold    uint32 //The size of the minimum total memory that must be freed in the process heap before it is freed (de-committed), in bytes. This value is advisory.
	LockPrefixTable               uint32 //The VA of a list of addresses where the LOCK prefix is used. These will be replaced by NOP on single-processor systems. This member is available only for x86.
	MaximumAllocationSize         uint32 //The maximum allocation size, in bytes. This member is obsolete and is used only for debugging purposes.
	VirtualMemoryThreshold        uint32 //The maximum block size that can be allocated from heap segments, in bytes.
	ProcessHeapFlags              uint32 //The process heap flags. For more information, see HeapCreate.
	ProcessAffinityMask           uint32 //The process affinity mask. For more information, see GetProcessAffinityMask. This member is available only for .exe files.
	CSDVersion                    uint16 //The service pack version.
	DependentLoadFlags            uint16
	EditList                      uint32 //Reserved for use by the system.
	SecurityCookie                uint32 //A pointer to a cookie that is used by Visual C++ or GS implementation.
	SEHandlerTable                uint32 //The VA of the sorted table of RVAs of each valid, unique handler in the image. This member is available only for x86.
	SEHandlerCount                uint32 //The count of unique handlers in the table. This member is available only for x86.

	//the following attributes are only present if _WIN64

	GuardCFCheckFunctionPointer              uint32
	GuardCFDispatchFunctionPointer           uint32
	GuardCFFunctionTable                     uint32
	GuardCFFunctionCount                     uint32
	GuardFlags                               uint32
	CodeIntegrity                            IMAGE_LOAD_CONFIG_CODE_INTEGRITY
	GuardAddressTakenIatEntryTable           uint32
	GuardAddressTakenIatEntryCount           uint32
	GuardLongJumpTargetTable                 uint32
	GuardLongJumpTargetCount                 uint32
	DynamicValueRelocTable                   uint32
	CHPEMetadataPointer                      uint32
	GuardRFFailureRoutine                    uint32
	GuardRFFailureRoutineFunctionPointer     uint32
	DynamicValueRelocTableOffset             uint32
	DynamicValueRelocTableSection            uint16
	Reserved2                                uint16
	GuardRFVerifyStackPointerFunctionPointer uint32
	HotPatchTableOffset                      uint32
	Reserved3                                uint32
	EnclaveConfigurationPointer              uint32
	VolatileMetadataPointer                  uint32
	GuardEHContinuationTable                 uint32
	GuardEHContinuationCount                 uint32
	GuardXFGCheckFunctionPointer             uint32
	GuardXFGDispatchFunctionPointer          uint32
	GuardXFGTableDispatchFunctionPointer     uint32
	CastGuardOsDeterminedFailureMode         uint32
	GuardMemcpyFunctionPointer               uint32
}

// ImageLoadConfig will return the IMAGE_LOAD_CONFIG_DIRECTORY structure of the PE
func (f *File) ImageLoadConfig() (*IMAGE_LOAD_CONFIG_DIRECTORY, error) {

	ds, idd := f.sectionFromDirectoryEntry(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)

	// didn't find a section, so no config dir was found
	if ds == nil {
		return nil, nil
	}

	sectionData, err := ds.Data()
	if err != nil {
		return nil, err
	}

	// seek to the virtual address specified in the data directory
	sectionData = sectionData[idd.VirtualAddress-ds.VirtualAddress:]

	configDir := IMAGE_LOAD_CONFIG_DIRECTORY{}
	err = binary.Read(bytes.NewReader(sectionData), binary.LittleEndian, &configDir)

	if err != nil {
		return nil, err
	}

	return &configDir, nil
}

type SDKVersion int

const (
	SDKVersionUnk = iota
	SDKVersion80
	SDKVersion81
	SDKVersion100NoInteg
	SDKVersion100NoCFG
	SDKVersion10010586Full
	SDKVersion10015063
)

// WinSDKVersion represents the specific version of Windows SDK used to build the PE file (if any). An error when getting the ImageLoadConfig structure will result in a SDKVersionUnk value. If it's important that you get an accurate value here, call the ImageLoadConfig function first and check the error. Pulled from here https://github.com/google/syzygy/blob/master/syzygy/pe/pe_structs.h#L88
func (f *File) WinSDKVersion() SDKVersion {
	ic, err := f.ImageLoadConfig()
	if err != nil || ic == nil {
		//eat the error
		return SDKVersionUnk
	}
	//these have all been observed on a mostly default win10 host, unsure what the weird sizes are, but the specific ones ref'd in the link above are produced
	//this is also probably not the greatest method of figuring it out, but we take what we can get
	switch ic.Size {
	case 72:
		return SDKVersion80
	case 92:
		return SDKVersion81
	case 104:
		// looks like 81 with code integ?
		return SDKVersionUnk
	case 112:
		return SDKVersion100NoCFG
	case 128:
		return SDKVersion10010586Full
	case 148:
		//last included:
		//Reserved2 uint16
		//GuardRFVerifyStackPointerFunctionPointer uint32
		return SDKVersionUnk
	case 152:
		//last included:
		//GuardRFVerifyStackPointerFunctionPointer uint32
		//HotPatchTableOffset uint32
		return SDKVersionUnk
	case 160:
		//last included:
		//Reserved3                                uint32
		//EnclaveConfigurationPointer              uint32
		return SDKVersionUnk
	case 164:
		//last included
		//EnclaveConfigurationPointer              uint32
		//VolatileMetadataPointer                  uint32
		return SDKVersionUnk
	case 172:
		//last included
		//		GuardEHContinuationTable uint32
		//GuardEHContinuationCount uint32
		return SDKVersionUnk
	case 184:
		//everything except:
		//CastGuardOsDeterminedFailureMode         uint32
		//GuardMemcpyFunctionPointer               uint32
		return SDKVersionUnk
	case 188:
		//everything except:
		//GuardMemcpyFunctionPointer uint32
		return SDKVersionUnk
	case 192:
		return SDKVersion10015063
	case 256:
		fallthrough
	case 264:
		fallthrough
	case 280:
		fallthrough
	case 304:
		fallthrough
	case 312:
		fallthrough
	case 320:
		return SDKVersionUnk
	}
	return SDKVersionUnk
}
