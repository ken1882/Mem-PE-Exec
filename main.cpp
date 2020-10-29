#include "main.h"
#include "util.h"

IMAGE_DOS_HEADER IDH;
IMAGE_NT_HEADERS32 INH32;
IMAGE_NT_HEADERS64 INH64;
std::vector<char> RawData;
std::fstream SourceFile;

void parseHeader32();
void parseHeader64();
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

    SourceFile.seekg(IDH.e_lfanew+sizeof(INH32), std::ios::beg);

    for(int i=0;i<section_size;++i){
        IMAGE_SECTION_HEADER tmp_ish;
        Util::LoadPEStructure(SourceFile, &tmp_ish, 0, false);
        auto addr = tmp_ish.VirtualAddress + INH32.OptionalHeader.ImageBase;

        std::cout << "Mapping section " << tmp_ish.Name << "\t=> " << (void*)addr << '\n';
        memcpy(
            LPVOID(addr),
            &tmp_ish,
            sizeof(tmp_ish)
        );
    }
    Util::Pause();
}

void parseHeader64(){

}

void parseImport32(){

}

void parseImport64(){

}
