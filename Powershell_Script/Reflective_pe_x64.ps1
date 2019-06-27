function Invoke-Reflective_x64
{
param(
[Parameter(Position = 0,Mandatory = $true)]
[byte[]]
$pe_bytes
)

$code =@"
using System;
using System.Runtime.InteropServices;


namespace PE
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public UInt32 VirtualAddress;
        public UInt32 SizeOfBlock;
    }
    
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public UInt32 OriginalFirstThunk;
        public UInt32 TimeDateStamp;
        public UInt32 ForwarderChain;
        public UInt32 Name;
        public UInt32 FirstThunk;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY
    {
        public UIntPtr StartAddressOfRawData;
        public UIntPtr EndAddressOfRawData;
        public UIntPtr AddressOfIndex;
        public UIntPtr AddressOfCallBacks;
        public UInt32 SizeOfZeroFill;
        public UInt32 Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        public UInt16 e_magic;       // Magic number
        public UInt16 e_cblp;    // Bytes on last page of file
        public UInt16 e_cp;      // Pages in file
        public UInt16 e_crlc;    // Relocations
        public UInt16 e_cparhdr;     // Size of header in paragraphs
        public UInt16 e_minalloc;    // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
        public UInt16 e_ss;      // Initial (relative) SS value
        public UInt16 e_sp;      // Initial SP value
        public UInt16 e_csum;    // Checksum
        public UInt16 e_ip;      // Initial IP value
        public UInt16 e_cs;      // Initial (relative) CS value
        public UInt16 e_lfarlc;      // File address of relocation table
        public UInt16 e_ovno;    // Overlay number
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=4)]
        public UInt16 [] e_res1;    // Reserved words
        public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;     // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=10)]
        public UInt16[] e_res2;    // Reserved words
        public Int32 e_lfanew;      // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Sequential,Size=8)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    public enum MachineType : ushort
    {
        Native = 0,
        I386 = 0x014c,
        Itanium = 0x0200,
        x64 = 0x8664
    }
    public enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    }
    public enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14

    }
    public enum DllCharacteristicsType : ushort
    {
        RES_0 = 0x0001,
        RES_1 = 0x0002,
        RES_2 = 0x0004,
        RES_3 = 0x0008,
        IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
        IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
        RES_4 = 0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    }

    

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        [FieldOffset(0)]
        public MagicType Magic;

        [FieldOffset(2)]
        public byte MajorLinkerVersion;

        [FieldOffset(3)]
        public byte MinorLinkerVersion;

        [FieldOffset(4)]
        public uint SizeOfCode;

        [FieldOffset(8)]
        public uint SizeOfInitializedData;

        [FieldOffset(12)]
        public uint SizeOfUninitializedData;

        [FieldOffset(16)]
        public uint AddressOfEntryPoint;

        [FieldOffset(20)]
        public uint BaseOfCode;

        [FieldOffset(24)]
        public ulong ImageBase;

        [FieldOffset(32)]
        public uint SectionAlignment;

        [FieldOffset(36)]
        public uint FileAlignment;

        [FieldOffset(40)]
        public ushort MajorOperatingSystemVersion;

        [FieldOffset(42)]
        public ushort MinorOperatingSystemVersion;

        [FieldOffset(44)]
        public ushort MajorImageVersion;

        [FieldOffset(46)]
        public ushort MinorImageVersion;

        [FieldOffset(48)]
        public ushort MajorSubsystemVersion;

        [FieldOffset(50)]
        public ushort MinorSubsystemVersion;

        [FieldOffset(52)]
        public uint Win32VersionValue;

        [FieldOffset(56)]
        public uint SizeOfImage;

        [FieldOffset(60)]
        public uint SizeOfHeaders;

        [FieldOffset(64)]
        public uint CheckSum;

        [FieldOffset(68)]
        public SubSystemType Subsystem;

        [FieldOffset(70)]
        public DllCharacteristicsType DllCharacteristics;

        [FieldOffset(72)]
        public ulong SizeOfStackReserve;

        [FieldOffset(80)]
        public ulong SizeOfStackCommit;

        [FieldOffset(88)]
        public ulong SizeOfHeapReserve;

        [FieldOffset(96)]
        public ulong SizeOfHeapCommit;

        [FieldOffset(104)]
        public uint LoaderFlags;

        [FieldOffset(108)]
        public uint NumberOfRvaAndSizes;

        [FieldOffset(112)]
        public IMAGE_DATA_DIRECTORY ExportTable;

        [FieldOffset(120)]
        public IMAGE_DATA_DIRECTORY ImportTable;

        [FieldOffset(128)]
        public IMAGE_DATA_DIRECTORY ResourceTable;

        [FieldOffset(136)]
        public IMAGE_DATA_DIRECTORY ExceptionTable;

        [FieldOffset(144)]
        public IMAGE_DATA_DIRECTORY CertificateTable;

        [FieldOffset(152)]
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;

        [FieldOffset(160)]
        public IMAGE_DATA_DIRECTORY Debug;

        [FieldOffset(168)]
        public IMAGE_DATA_DIRECTORY Architecture;

        [FieldOffset(176)]
        public IMAGE_DATA_DIRECTORY GlobalPtr;

        [FieldOffset(184)]
        public IMAGE_DATA_DIRECTORY TLSTable;

        [FieldOffset(192)]
        public IMAGE_DATA_DIRECTORY LoadConfigTable;

        [FieldOffset(200)]
        public IMAGE_DATA_DIRECTORY BoundImport;

        [FieldOffset(208)]
        public IMAGE_DATA_DIRECTORY IAT;

        [FieldOffset(216)]
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

        [FieldOffset(224)]
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

        [FieldOffset(232)]
        public IMAGE_DATA_DIRECTORY Reserved;
    }
    

    //IMAGE_NT_HEADERS structure

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS
    {
        public UInt32 Signature;
        public IMAGE_FILE_HEADER Fileheader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }



    //IMAGE_SECTION_HEADER structure
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;

        [FieldOffset(8)]
        public UInt32 VirtualSize;

        [FieldOffset(12)]
        public UInt32 VirtualAddress;

        [FieldOffset(16)]
        public UInt32 SizeOfRawData;

        [FieldOffset(20)]
        public UInt32 PointerToRawData;

        [FieldOffset(24)]
        public UInt32 PointerToRelocations;

        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;

        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;

        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;

        [FieldOffset(36)]
        public UInt32 Characteristics;
    }

}

"@

$func_code = @"

[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr VirtualAlloc(IntPtr address,UIntPtr size,UInt32 flAllocationType,UInt32 flProtect);

[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr Base,string Func_Name);

[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr LoadLibraryA(string dll);

[DllImport("kernel32.dll",SetLastError = true)]
public static extern bool WriteProcessMemory(IntPtr handle,IntPtr Address,IntPtr buffer,UIntPtr size,ref UIntPtr lpNumberOfBytesWritten);

[DllImport("kernel32.dll",SetLastError = true)]
public static extern bool VirtualFree(IntPtr lpAddress , UIntPtr dwSize ,UInt32 dwFreeType);

[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr GetCurrentProcess();

[DllImport("kernel32.dll",SetLastError = true)]
public static extern bool CloseHandle(IntPtr Handle);

"@


    Add-Type -TypeDefinition $code -Language CSharp
    $win32_Func = Add-Type -MemberDefinition $func_code -Name 'Win32_Func' -Namespace "WINAPI" -PassThru

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
            Param(
            [Parameter(Position = 0, Mandatory = $true)]
            [Int64]
            $Value1,
            
            [Parameter(Position = 1, Mandatory = $true)]
            [Int64]
            $Value2
            )
            
            [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
            [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
            [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

            if ($Value1Bytes.Count -eq $Value2Bytes.Count)
            {
                $CarryOver = 0
                for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
                {
                    $Val = $Value1Bytes[$i] - $CarryOver
                    #Sub bytes
                    if ($Val -lt $Value2Bytes[$i])
                    {
                        $Val += 256
                        $CarryOver = 1
                    }
                    else
                    {
                        $CarryOver = 0
                    }
                    
                    
                    [UInt16]$Sum = $Val - $Value2Bytes[$i]

                    $FinalBytes[$i] = $Sum -band 0x00FF
                }
            }
            else
            {
                Throw "Cannot subtract bytearrays of different sizes"
            }
            
            return [BitConverter]::ToInt64($FinalBytes, 0)
    }
        

    Function Add-SignedIntAsUnsigned
    {
            Param(
            [Parameter(Position = 0, Mandatory = $true)]
            [Int64]
            $Value1,
            
            [Parameter(Position = 1, Mandatory = $true)]
            [Int64]
            $Value2
            )
            
            [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
            [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
            [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

            if ($Value1Bytes.Count -eq $Value2Bytes.Count)
            {
                $CarryOver = 0
                for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
                {
                    #Add bytes
                    [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                    $FinalBytes[$i] = $Sum -band 0x00FF
                    
                    if (($Sum -band 0xFF00) -eq 0x100)
                    {
                        $CarryOver = 1
                    }
                    else
                    {
                        $CarryOver = 0
                    }
                }
            }
            else
            {
                Throw "Cannot add bytearrays of different sizes"
            }
            
            return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Convert-UIntToInt
    {
            Param(
            [Parameter(Position = 0, Mandatory = $true)]
            [UInt64]
            $Value
            )
            
            [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
            return ([BitConverter]::ToInt64($ValueBytes, 0))
    }

    Function Convert-Int16ToUInt16
    {
            Param(
            [Parameter(Position = 0, Mandatory = $true)]
            [Int16]
            $Value
            )
            
            [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
            return ([BitConverter]::ToUInt16($ValueBytes, 0))
    }

  
    function Get-DelegateType {
        
        Param (
            [OutputType([Type])]
        
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
        
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )
        
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        return $TypeBuilder.CreateType()
        }

    

        function Fix-Relocation 
        {
            param(
                [Parameter(Position = 0 , Mandatory = $true)]
                [IntPtr]
                $pe_base,


                [Parameter(Position = 1 , Mandatory = $true)]
                [UInt32]
                $base_rva,

                [Parameter(Position = 2 , Mandatory = $true)]
                [System.IntPtr]
                $orig_base

            )
            
            $base_rel_type = 10

            if([System.IntPtr]::Size -eq 4)
            {
                $base_rel_type = 3
            }

            if($base_rva -eq 0)
            {
                return 0
            }

            $delta = Sub-SignedIntAsUnsigned $pe_base $orig_base

            $reloc_ptr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $base_rva)
            $reloc_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($reloc_ptr,[Type][PE.IMAGE_BASE_RELOCATION])

            while ($reloc_struct.VirtualAddress) 
            {
                $addr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $reloc_struct.VirtualAddress)
                $number_of_entry = ($reloc_struct.SizeOfBlock - ([UInt32]8)) /2
                $entry_ptr = Add-SignedIntAsUnsigned $reloc_ptr 8

                echo "Number Of Entry $number_of_entry"
                for($i=0;$i -lt $number_of_entry ; $i++)
                {
                    $type = Convert-Int16ToUInt16 $([System.Runtime.InteropServices.Marshal]::ReadInt16($entry_ptr))
                    if( $($type -shr 12) -eq $base_rel_type)
                    {
                        $offset = $type -band 0xfff
                        $src_addr = Add-SignedIntAsUnsigned $addr $offset
                        $data = Add-SignedIntAsUnsigned $([System.Runtime.InteropServices.Marshal]::ReadIntPtr($src_addr)) $delta
                        [System.Runtime.InteropServices.Marshal]::WriteIntPtr($src_addr,$data)
                        echo "`t Offset: $([System.Convert]::ToString($offset,16))"
                    }
                    $entry_ptr = Add-SignedIntAsUnsigned $entry_ptr 2
                }
                $reloc_ptr = Add-SignedIntAsUnsigned $reloc_ptr $(Convert-UIntToInt $reloc_struct.SizeOfBlock)
                $reloc_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($reloc_ptr,[Type][PE.IMAGE_BASE_RELOCATION])
            }

            return 1
        }



        function Load-Import {
            param (
                [Parameter(Position = 0 , Mandatory = $true)]
                [System.IntPtr]
                $pe_base,

                [Parameter(Position = 1 , Mandatory = $true)]
                [UInt32]
                $import_rva
            )

            $ordinal_flag = 0x8000000000000000

            if([UintPtr]::Size -eq 4)
            {
                $ordinal_flag = 0x80000000
            }

            if($import_rva -eq 0)
            {
                return 0
            }

            $import_ptr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_rva)
            $import_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($import_ptr,[Type][PE.IMAGE_IMPORT_DESCRIPTOR])

            while($import_struct.Name)
            {
                $dll_name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi( $(Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_struct.Name) ) ) 
                $dll = $win32_Func::LoadLibraryA($dll_name)
                if ($dll -eq 0)
                {
                    echo "[-]Failed To Load $dll_name"
                    return 0
                }

                echo "`n[+]From $dll_name"
                $Othunk = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_struct.OriginalFirstThunk)
                $Fthunk = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_struct.FirstThunk)

                if($import_struct.OriginalFirstThunk -eq 0)
                {
                    $Othunk = $Fthunk
                }
                $AddressOfData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Othunk,[Type][UIntPtr])

                while ($AddressOfData.ToUInt64() -ne 0 )
                {
                    if($AddressOfData.ToUInt64() -band $ordinal_flag)
                    {
                        $func_addr = $win32_Func::GetProcAddress($dll,$($AddressOfData -band 0xffff))
                        [System.Runtime.InteropServices.Marshal]::WriteIntPtr($Fthunk,$func_addr)

                        echo "[+]Loading Function Using Ordinal $($AddressOfData -band 0xffff)"
                    }
                    else 
                    {
                        $func_name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($(Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $AddressOfData)) +2)
                        $func_addr = $win32_Func::GetProcAddress($dll,$func_name)
                        [System.Runtime.InteropServices.Marshal]::WriteIntPtr($Fthunk,$func_addr)
                        
                        
                        echo "[+]Loading $func_name"
                    }

                    $Othunk = Add-SignedIntAsUnsigned $Othunk $([IntPtr]::Size)
                    $Fthunk = Add-SignedIntAsUnsigned $Fthunk $([IntPtr]::Size)
                    $AddressOfData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Othunk,[Type][UIntPtr])
                }

                $import_ptr = Add-SignedIntAsUnsigned $import_ptr $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][PE.IMAGE_IMPORT_DESCRIPTOR]))
                $import_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($import_ptr,[Type][PE.IMAGE_IMPORT_DESCRIPTOR])
            }
            
        }
    

        function Call-Tls {
            param (
                
                [Parameter(Position = 0 , Mandatory = $true)]
                [System.IntPtr]
                $pe_buf ,

                [Parameter(Position = 1 , Mandatory = $true)]
                [UInt32]
                $tls_rva
            )

            $tls_deleg = Get-DelegateType @([System.IntPtr],[UInt32],[System.IntPtr]) ([bool])

            if( $tls_rva -eq 0)
            {
                return 0
            }

            $tls_ptr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $tls_rva)
            $tls_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tls_ptr,[Type][PE.IMAGE_TLS_DIRECTORY])

            $tls_callback_ptr = Convert-UIntToInt $tls_struct.AddressOfCallBacks

            if($(Convert-UIntToInt $tls_callback_ptr) -eq 0)
            {
                return 1
            }
            $func_addr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($tls_callback_ptr)

            while($func_addr -ne 0)
            {
                $exec_func = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($func_addr, $tls_deleg)
                $exec_func.Invoke($pe_base,1,0)

                $tls_callback_ptr = Add-SignedIntAsUnsigned $tls_callback_ptr $([IntPtr]::Size)
                $func_addr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($tls_callback_ptr)
            }
            
            return 1
        }

        function Execute-Entry {
            param (
                
                [Parameter(Position = 0 , Mandatory = $true)]
                [System.IntPtr]
                $pe_buf ,

                [Parameter(Position = 1 , Mandatory = $true)]
                [UInt32]
                $addessofentry ,

                [Parameter(Position = 2 , Mandatory = $true)]
                [UInt32]
                $Charactaristic
            )
            
            $dll_deleg = Get-DelegateType @([System.IntPtr],[UInt32],[System.IntPtr]) ([bool])
            $exe_deleg = Get-DelegateType @([IntPtr]) ([void])


            if($addessofentry -eq 0)
            {
                return 0
            }

            $entry_addr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $addessofentry)

            if($Charactaristic -band 0x2000)
            {
                echo "[!]File Is Dll"
                $exec_func = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($entry_addr, $dll_deleg)
                $exec_func.Invoke($pe_base,1,0)
            }
            else
            {
                echo "[!]File is Exe"
                $exec_func = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($entry_addr, $exe_deleg)
                $exec_func.Invoke(0)
            }

        }
    #Main Task
    #---------------------------------------------------------------------------------

    [System.IntPtr]$pe_buf = 0
    [System.IntPtr]$pe_base = 0
    
    
    
    $cur_proc = $win32_Func::GetCurrentProcess()

    try {
        $pe_buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pe_bytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($pe_bytes,0,$pe_buf,$pe_bytes.Length)
    }
    catch {
        Write-Output "failed To Allocate Memory Or Failed To Copy Into Memory";return
    }


    $dos_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pe_buf,[Type][PE.IMAGE_DOS_HEADER])
    if($dos_struct.e_magic -ne 23117)
    {
        Write-Output "Invalid File";[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf);return
    }

    $nt_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($(Add-SignedIntAsUnsigned $pe_buf $(Convert-UIntToInt $dos_struct.e_lfanew)),[Type][PE.IMAGE_NT_HEADERS])
    if($nt_struct.OptionalHeader.Magic -ne [PE.MagicType]::IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        Write-Output "This is not x64 pe";[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf);return
    }
    $require_relocation = 0
    $pe_base = $win32_Func::VirtualAlloc($(Convert-UIntToInt $nt_struct.OptionalHeader.ImageBase),$nt_struct.OptionalHeader.SizeOfImage,0x00001000 -bor 0x00002000,0x40)

    if($pe_base -eq 0)
    {
        $require_relocation = 1
        $pe_base = $win32_Func::VirtualAlloc(0,$nt_struct.OptionalHeader.SizeOfImage,0x00001000 -bor 0x00002000,0x40)
        if($pe_base -eq 0 )
        {
            Write-Output "Failed To Allocate Memory";[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf);return
        }
    }

    echo "Writing Header"
    $win32_Func::WriteProcessMemory($cur_proc,$pe_base,$pe_buf,$nt_struct.OptionalHeader.SizeOfHeaders,[ref]([UInt32]0)) | Out-Null

    echo 'Writing Sections'
    $sec_ptr = $(Add-SignedIntAsUnsigned $pe_buf $(Convert-UIntToInt $dos_struct.e_lfanew))
    $sec_ptr = Add-SignedIntAsUnsigned $sec_ptr $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][PE.IMAGE_NT_HEADERS]))

    for($i=0;$i -lt $nt_struct.Fileheader.NumberOfSections;$i++)
    {
        $sec_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($sec_ptr,[Type][PE.IMAGE_SECTION_HEADER])

        $src = Add-SignedIntAsUnsigned $pe_buf $(Convert-UIntToInt $sec_struct.PointerToRawData)
        $dest = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $sec_struct.VirtualAddress)

        $name = [System.String]::new($sec_struct.Name,0,8)
        echo "[+]Coping $name"
        $win32_Func::WriteProcessMemory($cur_proc,$dest,$src,$sec_struct.SizeOfRawData,[ref]([UInt32]0)) | Out-Null
        $sec_ptr = Add-SignedIntAsUnsigned $sec_ptr $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][PE.IMAGE_SECTION_HEADER]))
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf)
    $load_status = 1
    if($require_relocation -eq 1)
    {
        echo "`n[+]Relocating Base"
        $load_status = Fix-Relocation $pe_base $nt_struct.OptionalHeader.BaseRelocationTable.VirtualAddress $(Convert-UIntToInt $nt_struct.OptionalHeader.ImageBase)
    }
    
    echo "[+]Loading Imports"
    $load_status = Load-Import $pe_base $nt_struct.OptionalHeader.ImportTable.VirtualAddress

    echo "[+]Calling TLS Callbacks"
    $load_status = Call-Tls $pe_base $nt_struct.OptionalHeader.TLSTable.VirtualAddress

    if($load_status -eq 1)
    {
        Execute-Entry $pe_buf $nt_struct.OptionalHeader.AddressOfEntryPoint $nt_struct.Fileheader.Characteristics | Out-Null
    }
    

    $win32_Func::VirtualFree($pe_base,([UInt32]0),0x00008000) | Out-Null
    $win32_Func::CloseHandle($cur_proc) | Out-Null

}

