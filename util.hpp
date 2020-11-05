#include "main.h"

namespace Util{
    /**
     * > Load a PE struct
     * @param [file] File IO stream of the PE
     * @param [strptr] Output struct
     * @param [offset=0] Seek offset to the current file stream
     * @param [rewind=false] Rewind the current file stream
     */
    template<class T>
    void LoadPEStructure(std::fstream& file, T* strptr, int offset, bool rewind){
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));
        auto s_type = rewind ? std::ios::beg : std::ios::cur;
        file.seekg(offset, s_type);
        file.read(buffer, sizeof(T));
        memcpy(strptr, buffer, sizeof(T));
    }
    /**
     * > Return the raw data of given (PE) file
     * @param [path] Path to the file
     */
    std::vector<char> LoadPEBuffer(const char* path){
        std::fstream fs(path, std::ios::in | std::ios::binary);
        std::vector<char> ret;
        if(fs.is_open()){
            std::vector<char> buffer(
                (std::istreambuf_iterator<char>(fs)),
                std::istreambuf_iterator<char>()
            );
            ret = buffer;
        }
        return ret;
    }

    char Pause(){
        std::cout << "\n\nPress any key to continue...";
        char _ = getch();
        std::cout << '\n' << std::endl;
    }

    char Pause(std::string hint){
        std::cout << hint;
        char _ = getch();
        std::cout << '\n' << std::endl;
    }
}
