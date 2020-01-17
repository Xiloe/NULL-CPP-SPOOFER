#include <iostream>
#include <fstream>
#include <filesystem>
#include <urlmon.h>
#include <wininet.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

bool Exists(const std::string& filename) {
    std::ifstream ifile(filename.c_str());
    return (bool)ifile;

}

int main(int argc, char** argv)
{
    SetConsoleTitleA("Null Mapper 1.0 | Made By 0x00#3042");

    if (argc != 4)
    {
        std::cout << "[!] Uh Oh, Stinky...  Correct usage: Null.exe <C:\\full\\path\\driver.sys>.\n";
        return -1;
    }

    if (argc == 2)
    {
        std::cout << "[!] Pr0 cracker man" << std::endl;
        system("pause");
        return -1;
    }

    const std::string driver_path = argv[1];
    const std::string driver_name = argv[2];
    const std::string secret_word = argv[3];

    if (Exists(driver_path) != 1)
    {
        std::cout << "[-] Uh Oh, Stinky...  File \"" << driver_path << "\" doesn't exist." << std::endl;
        return -1;
    }

    if (secret_word == "(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+(+!+[])+(+[])+(+[])+(+[]))+[])[+[]]")
    {
        char Buffer[256];

        if (snprintf(Buffer, sizeof(Buffer), "sc create %s binPath=\"%s\" type=kernel && sc start %s && sc delete %s && cls", driver_name, argv[1], driver_name, driver_name) >= sizeof(Buffer))
        {
            std::cout << "[-] Uh Oh, Stinky...  Buffer isn't big enough." << std::endl;
        }
        else
        {
            system(Buffer);
        }
        std::cout << "[+] Successfully Mapped.\n";
        system("pause");
    }
    else {
        std::cout << "[!] Pr0 cracker man" << std::endl;
        system("pause");
        return -1;
    }
}