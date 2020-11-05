#include "main.h"
#include "util.h"

IMAGE_DOS_HEADER IDH;
IMAGE_NT_HEADERS32 INH32;
IMAGE_NT_HEADERS64 INH64;
std::vector<char> RawData;
std::fstream SourceFile;

void parseHeader32();
void parseHeader64();
void applyRelocation32();
void applyRelocation64();
void parseImport32();
void parseImport64();
void makeX86JumpPoint(std::vector<std::pair<std::string, std::string>>&);

int main(int argc, char* argv[], char** envp){
    std::string target_file = "sample/HxD_azo.exe";
    SourceFile.open(target_file, std::ios::in | std::ios::binary);

    Util::LoadPEStructure(SourceFile, &IDH);
    Util::LoadPEStructure(SourceFile, &INH32, IDH.e_lfanew, true);
    Util::LoadPEStructure(SourceFile, &INH64, IDH.e_lfanew, true);
    const bool IsX64PE = (INH64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    IMAGE_DATA_DIRECTORY reloc_dir;

    const DWORD ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    RawData = Util::LoadPEBuffer(target_file.c_str());

    // Load x64 header
    if(IsX64PE){
        QWORD newImagebase = 0;
        std::cout << "Selected image is 64-bits PE\n";
        std::cout << "Image Base: " << (void*)INH64.OptionalHeader.ImageBase << '\n';
        newImagebase = (QWORD)VirtualAlloc((LPVOID)INH64.OptionalHeader.ImageBase, INH64.OptionalHeader.SizeOfImage, ALLOC_TYPE, PAGE_EXECUTE_READWRITE);
        reloc_dir = INH64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        // Relocate if reloc table available and prefer address occupied
        if(!newImagebase && reloc_dir.VirtualAddress){
            auto _msize = INH64.OptionalHeader.SizeOfImage;
            std::cout << "Prefer address occupied, relocating (x64, size: " << (void*)_msize << ")\n";
            newImagebase = (QWORD)VirtualAlloc(NULL, INH64.OptionalHeader.SizeOfImage, ALLOC_TYPE, PAGE_EXECUTE_READWRITE);
            INH64.OptionalHeader.ImageBase = newImagebase;

            std::cout << "New image base is: " << (void*)newImagebase << '\n';
        }
        parseHeader64();
        applyRelocation64();
        parseImport64();
    }
    else{ // x86 header
        DWORD newImagebase = 0;
        std::cout << "Selected image is 32-bits PE\n";
        std::cout << "Image Base: " << (void*)INH32.OptionalHeader.ImageBase << '\n';
        newImagebase = (QWORD)VirtualAlloc((LPVOID)INH32.OptionalHeader.ImageBase, INH32.OptionalHeader.SizeOfImage, ALLOC_TYPE, PAGE_EXECUTE_READWRITE);
        reloc_dir = INH32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if(!newImagebase && reloc_dir.VirtualAddress){
            auto _msize = INH32.OptionalHeader.SizeOfImage;
            std::cout << "Prefer address occupied, relocating (x86, size: " << (void*)_msize << ")\n";
            newImagebase = (QWORD)VirtualAlloc(NULL, _msize, ALLOC_TYPE, PAGE_EXECUTE_READWRITE);
            INH32.OptionalHeader.ImageBase = newImagebase;
            std::cout << "New image base is: " << (void*)newImagebase << '\n';
        }
        parseHeader32();
        applyRelocation32();
        parseImport32();
    }

    SourceFile.close();
    return 0;
}

void parseHeader32(){
    std::cout << "Parsing headers\n";
    memcpy(
        (void*)INH32.OptionalHeader.ImageBase,
        RawData.data(),
        INH32.OptionalHeader.SizeOfHeaders
    );
    DWORD* e_lfanew = (DWORD*)(INH32.OptionalHeader.ImageBase+0x3c);

    // Fix imagebase location
    uintptr_t ioh_addr = INH32.OptionalHeader.ImageBase + *e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    IMAGE_OPTIONAL_HEADER32* _ioh32 = (IMAGE_OPTIONAL_HEADER32*)ioh_addr;
    _ioh32->ImageBase = INH32.OptionalHeader.ImageBase;

    int section_size = INH32.FileHeader.NumberOfSections;
    int header_offset = IDH.e_lfanew+sizeof(INH32);
    SourceFile.seekg(header_offset, std::ios::beg);

    int header_addr = INH32.OptionalHeader.ImageBase + header_offset;
    std::cout << "Section Headers: " << (void*)header_addr << '\n';

    for(int i=0;i<section_size;++i){
        IMAGE_SECTION_HEADER* ISH = (IMAGE_SECTION_HEADER*)header_addr;
        auto dst_addr = ISH->VirtualAddress + INH32.OptionalHeader.ImageBase;
        auto src_addr = (uintptr_t)RawData.data() + ISH->PointerToRawData;
        std::cout << "Mapping section " << ISH->Name << "\t=> " << (void*)dst_addr << '\n';
        memcpy(
            LPVOID(dst_addr),
            LPVOID(src_addr),
            ISH->SizeOfRawData
        );
        header_addr += sizeof(IMAGE_SECTION_HEADER);
    }

}


void applyRelocation32(){
    std::cout << "Apply relocation\n";
    IMAGE_DATA_DIRECTORY reloc_dir = INH32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(!reloc_dir.VirtualAddress || !reloc_dir.Size){ return ;}
    auto reloc_addr = INH32.OptionalHeader.ImageBase + reloc_dir.VirtualAddress;

    uintptr_t cur_offset = 0;
    uintptr_t upbound_addr = INH32.OptionalHeader.ImageBase + INH32.OptionalHeader.SizeOfImage;

    while(cur_offset < reloc_dir.Size){
        IMAGE_BASE_RELOCATION* IBR = (IMAGE_BASE_RELOCATION*)(reloc_addr + cur_offset);
        uintptr_t entry_len = (IBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
        BASE_RELOCATION_ENTRY* BRE = (BASE_RELOCATION_ENTRY*)((uintptr_t)IBR + sizeof(IMAGE_BASE_RELOCATION));
        for(int i=0;i<entry_len;++i){
            if(BRE == NULL){ break; }
            auto offset = BRE->Offset;
            auto type   = BRE->Type;
            uintptr_t page_addr = reloc_addr + offset;

            if(!offset){ break; }
            else if(type != RELB_HIGHLOW){
                std::cout << "Unsupported relocation at " << (void*)page_addr << " of " << type << '\n';
                continue;
            }
            else if(page_addr > upbound_addr){
                std::cout << "Relocation out of bound at " << (void*)page_addr << " of " << (void*)upbound_addr << '\n';
                continue;
            }
            BRE = (BASE_RELOCATION_ENTRY*)((uintptr_t)BRE + sizeof(BASE_RELOCATION_ENTRY));
        }
        cur_offset += IBR->SizeOfBlock;
    }
    std::cout << "Relocation done, total size: " << (void*)cur_offset << '\n';
}

void parseImport32(){
    std::cout << "Resolving imports\n";
    IMAGE_DATA_DIRECTORY import_dir = INH32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!import_dir.Size){
        std::cout << "Import directory not present.\n";
        return ;
    }

    auto import_addr = import_dir.VirtualAddress + INH32.OptionalHeader.ImageBase;
    std::cout << "Import Directory located at: " << (void*) import_addr << " (" << (void*)import_dir.Size << ")\n";

    std::vector<std::pair<std::string, std::string>> dll_functions;
    uintptr_t cur_offset = 0;
    uintptr_t upbound_addr = INH32.OptionalHeader.ImageBase + INH32.OptionalHeader.SizeOfImage;
    auto delta_idesc_offset = sizeof(IMAGE_IMPORT_DESCRIPTOR);
    while(cur_offset < import_dir.Size){
        IMAGE_IMPORT_DESCRIPTOR* IMD = (IMAGE_IMPORT_DESCRIPTOR*)(import_addr+cur_offset);

        // Terminating flag
        if(IMD->OriginalFirstThunk == NULL && IMD->FirstThunk == NULL){
            break;
        }

        char* dll_name = (char*)(IMD->Name+INH32.OptionalHeader.ImageBase);
        std::cout << "Importing: " << dll_name << '\n';

        // Import Name Table and Import Address Table offset
        auto INT_offset = IMD->FirstThunk;
        auto IAT_offset = IMD->OriginalFirstThunk;
        if(INT_offset == NULL){INT_offset = IAT_offset;}

        uintptr_t table_offset = 0;
        auto delta_table_offset = sizeof(IMAGE_THUNK_DATA32);
        const auto IBASE = INH32.OptionalHeader.ImageBase;

        while(true){
            IMAGE_THUNK_DATA32* INT_THUNK32 = (IMAGE_THUNK_DATA32*)(IBASE+INT_offset+table_offset);
            IMAGE_THUNK_DATA32* IAT_THUNK32 = (IMAGE_THUNK_DATA32*)(IBASE+IAT_offset+table_offset);
            table_offset += delta_table_offset;

            bool FLAG_IMPORT_BY_ORDINAL = IAT_THUNK32->u1.Ordinal & IMAGE_ORDINAL_FLAG32;
            std::cout << (void*)INT_THUNK32 << ' ' << (void*)IAT_THUNK32 << '\n';
            // Import by ordinal
            if(FLAG_IMPORT_BY_ORDINAL){
                auto lib_addr = LoadLibraryA(dll_name);
                char* fname = (char*)IMAGE_ORDINAL32(IAT_THUNK32->u1.Ordinal);
                uintptr_t faddr = (uintptr_t)GetProcAddress(lib_addr, fname);
                INT_THUNK32->u1.Function = faddr;
                std::cout << "Function " << fname << " loaded at " << (void*)faddr << ' ';
                std::cout << INT_THUNK32->u1.Function << '\n';
            }

            if(INT_THUNK32->u1.Function == NULL){break;}

            // Import by name
            if(!FLAG_IMPORT_BY_ORDINAL && INT_THUNK32->u1.Function == IAT_THUNK32->u1.Function){
                IMAGE_IMPORT_BY_NAME* IMN = (IMAGE_IMPORT_BY_NAME*)(IBASE+IAT_THUNK32->u1.AddressOfData);
                auto fname = (char*)IMN->Name;
                auto lib_addr = LoadLibraryA(dll_name);
                uintptr_t faddr = (uintptr_t)GetProcAddress(lib_addr, fname);

                // Function (probably) not in this library
                if(!faddr){break;}
                INT_THUNK32->u1.Function = faddr;
                std::cout << "Function " << fname << " loaded at " << (void*)faddr << ' ';
                std::cout << (void*)INT_THUNK32->u1.Function << '\n';
            }
        }
        std::cout << "------------------\n";
        cur_offset += delta_idesc_offset;
    }
    makeX86JumpPoint(dll_functions);
    Util::Pause();
}

void makeX86JumpPoint(std::vector<std::pair<std::string, std::string>>& dll_functions){
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const int SYS_PAGE_SIZE = sysInfo.dwPageSize;
    std::cout << "System page size: " << (void*)SYS_PAGE_SIZE << '\n';
    auto jmp_addr = VirtualAlloc(LPVOID(0xc7c95bf0), 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    std::cout << (void*)jmp_addr << '\n';
}

void applyRelocation64(){

}

void parseHeader64(){

}

void parseImport64(){

}
/*
0x7fffc7c95bf0 0xc7c95bf0
0x7fffc7c95cb0 0xc7c95cb0
*/
