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

    uintptr_t cur_ptr = 0;
    uintptr_t upbound_addr = INH32.OptionalHeader.ImageBase + INH32.OptionalHeader.SizeOfImage;

    while(cur_ptr < reloc_dir.Size){
        IMAGE_BASE_RELOCATION* IBR = (IMAGE_BASE_RELOCATION*)(reloc_addr + cur_ptr);
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
        cur_ptr += IBR->SizeOfBlock;
    }
    std::cout << "Relocation done, total size: " << (void*)cur_ptr << '\n';
    Util::Pause();
}

void parseImport32(){
    std::cout << "Resolving imports\n";
    IMAGE_DATA_DIRECTORY import_dir = INH32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

}

void applyRelocation64(){

}

void parseHeader64(){

}

void parseImport64(){

}
