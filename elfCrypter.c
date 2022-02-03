#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libelf.h>
#include <pthread.h>

#define ENTRY_POINT ((unsigned char*)0x400000)
#define _SC_PAGESIZE 11
#define LOADER_SIZE 0xc0

Elf64_Shdr stubSectionHeader = {
        .sh_name = (uint32_t)4,
        .sh_type = (uint32_t)SHT_PROGBITS,
        .sh_flags = (uint64_t)SHF_EXECINSTR | SHF_ALLOC,
        .sh_addr = (Elf64_Addr)0,
        .sh_offset = (Elf64_Off)0,
        .sh_size = (uint64_t)0,
        .sh_link = (uint32_t)0,
        .sh_info = (uint32_t)0,
        .sh_addralign = (uint64_t)16,
        .sh_entsize = (uint64_t)0,
};

void encryptBuf(char* myBuf, int length, char key)
{
    int i;
    for (i = 0; i < length; i++)
    {

        *myBuf ^= key;
        myBuf += 1;
        //printf("%c", *myBuf);
    }
    printf("myBuf: %p\n", myBuf);
    printf("final i (hex): %x\n", i);
    //printf("\n");
}

int encryptFile(const char* filePath)
{
    printf("%d\n", sizeof(long int));
    printf("sizeeeeee: %d\n", sizeof(unsigned long int));
    // --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    //char* myShellCode = "\xf3\x0f\x1e\xfa\x55\x48\x89\xE5\x48\x83\xEC\x20\xC7\x45\xEC\x00\x00\x40\x00\x8B\x45\xEC\x83\xC0\x08\x48\x98\x8B\x00\x48\x31\xF6\x89\xC6\x8B\x45\xEC\x83\xC0\x0C\x48\x98\x8B\x00\x48\x31\xFF\x89\xC7\x48\x31\xC9\x48\x31\xDB\x48\x31\xD2\x4D\x31\xC0\x49\x89\xF0\xB3\x05\xEB\x0B\x67\x30\x1E\x48\x83\xC6\x01\x48\x83\xC1\x01\x48\x39\xF9\x7C\xF0\x5D\x48\x83\xC4\x14\x4C\x8B\x0D\x03\x00\x00\x00\x41\xFF\xE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    //char* myShellCode = "\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x8B\x05\x6a\x00\x00\x00\x48\x98\x48\x31\xF6\x89\xC6\x48\x8B\x05\x60\x00\x00\x00\x83\xC0\x0C\x48\x98\x48\x31\xFF\x89\xC7\x48\x31\xC9\x48\x31\xDB\x48\x31\xD2\x4D\x31\xC0\x49\x89\xF0\xB3\x05\xEB\x0B\x67\x30\x1E\x48\x83\xC6\x01\x48\x83\xC1\x01\x48\x39\xF9\x7C\xF0\x5D\x48\x83\xC4\x14\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x5d\x48\x83\xc4\x04\x48\x8B\x05\x16\x00\x00\x00\x49\x89\xC1\x48\x31\xc0\x41\xFF\xE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    //char* myShellCode = "\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x8B\x05\x74\x00\x00\x00\x48\x98\x48\x31\xF6\x48\x89\xC6\x48\x8B\x05\x6d\x00\x00\x00\x48\x83\xC0\x0C\x48\x98\x48\x31\xFF\x48\x89\xC7\x48\x31\xC9\x48\x31\xDB\x48\x31\xD2\x4D\x31\xC0\x49\x89\xF0\xB3\x05\xE9\x00\x00\x00\x00\x30\x1E\x48\x83\xC6\x01\x48\x83\xC1\x01\x48\x39\xF9\x7C\xF1\x5D\x48\x83\xC4\x14\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x5D\x48\x83\xC4\x04\x48\x8B\x05\x1e\x00\x00\x00\x49\x89\xC1\x48\x31\xC0\x41\xFF\xE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    //char* myShellCode = "\xE8\x9b\x00\x00\x00\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x8B\x05\x84\x00\x00\x00\x4C\x01\xD0\x48\x31\xF6\x48\x89\xC6\x48\x8B\x05\x7c\x00\x00\x00\x4C\x01\xD0\x48\x83\xC0\x0C\x48\x31\xFF\x48\x89\xC7\x48\x31\xC9\x48\x31\xDB\x48\x31\xD2\x4D\x31\xC0\x49\x89\xF0\xB3\x05\xE9\x00\x00\x00\x00\x30\x1E\x48\x83\xC6\x01\x48\x83\xC1\x01\x48\x39\xF9\x0F\x8C\x00\x00\x00\x00\x5D\x48\x83\xC4\x14\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x5D\x48\x83\xC4\x04\x48\x8B\x05\x1E\x00\x00\x00\x49\x89\xC1\x48\x31\xC0\x41\xFF\xE1\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x4C\x8B\x14\x24\x49\x83\xEA\x05\xC3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    char* myShellCode = "\xE8\xab\x00\x00\x00\x4C\x2B\x15\x9c\x00\x00\x00\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x8B\x05\x75\x00\x00\x00\x4C\x01\xD0\x48\x31\xF6\x48\x89\xC6\x48\x8B\x05\x6d\x00\x00\x00\x48\x83\xC0\x0C\x48\x31\xFF\x48\x89\xC7\x48\x31\xC9\x48\x31\xDB\x48\x31\xD2\x4D\x31\xC0\x49\x89\xF0\xB3\x05\xE9\x00\x00\x00\x00\x30\x1E\x48\x83\xC6\x01\x48\x83\xC1\x01\x48\x39\xF9\x7C\xF1\x5D\x48\x83\xC4\x14\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x5D\x48\x83\xC4\x04\x48\x8B\x05\x20\x00\x00\x00\x4C\x01\xD0\x49\x89\xC1\x48\x31\xC0\x41\xFF\xE1\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x4C\x8B\x14\x24\x49\x83\xEA\x05\xC3\x90\x90\x90\x90\x90\x90\x90";
    char *p;
    FILE* pFile;
    Elf64_Ehdr* header;
    int i;
    char* sectionName;
    int fd = open("/home/roy/regular", O_RDONLY);
    int isTextSection;

    // Get the size of the file in 'filePath'
    struct stat buf;
    fstat(fd, &buf);
    off_t size = buf.st_size;
    // Open the file and read its content
    p = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    // Get the header of the file and check if the file is an ELF
    header = (Elf64_Ehdr*)p;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
    {
        printf("Invalid ELF file!\n");
        return 0;
    }

    // Read the Program Head\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x8B\x05\x73\x90\x00\x00\x48\x31\xF6\x48\x89\xC6\x48\x8B\x05\x6e\x00\x00\x00\x48\x83\xC0\x0C\x48\x31\xFF\x48\x89\xC7\x48\x31\xC9\x48\x31\xDB\x48\x31\xD2\x4D\x31\xC0\x49\x89\xF0\xB3\x05\xE9\x00\x00\x00\x00\x30\x1E\x48\x83\xC6\x01\x48\x83\xC1\x01\x48\x39\xF9\x7C\xF1\x5D\x48\x83\xC4\x14\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x5D\x48\x83\xC4\x04\x48\x8B\x05\x1e\x00\x00\x00\x49\x89\xC1\x48\x31\xC0\x41\xFF\xE1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00er Table
    Elf64_Phdr* phdr[header->e_phnum];
    for (i = 0; i < header->e_phnum; i++)
    {
        phdr[i] = (Elf64_Phdr*)(p + header->e_phoff + i * header->e_phentsize);
    }

    // Read the Section Header Table
    Elf64_Shdr* stringTable = (Elf64_Shdr*) (p + header->e_shoff +
                                             header->e_shstrndx * header->e_shentsize);
    Elf64_Shdr* shdr[header->e_shnum];
    for (i = 0; i < header->e_shnum; i++)
    {
        shdr[i] = (Elf64_Shdr *) (p + header->e_shoff + i * header->e_shentsize);
    }

    int textSectionIndex;
    isTextSection = 0;
    for (i = 0; i < header->e_shnum; i++)
    {
        //printf("\n");
        sectionName = p + stringTable->sh_offset + shdr[i]->sh_name;

        // Check if the current section is the .text section (which contains the code)
        if (!strcmp(sectionName, ".text"))
        {
            encryptBuf(p + shdr[i]->sh_offset, shdr[i]->sh_size, 0x5);

            // We store the address and the size of the .text section in the reserved bytes in the ELF header
            //*((int *)(p + 0x08)) = ENTRY_POINT + shdr[i]->sh_offset; // We can also use shdr[i]->sh_addr
            //*((int *)(p + 0x0c)) = shdr[i]->sh_size;

            textSectionIndex = i;

            close(fd);

            isTextSection = 1;

            break;
        }
    }
    if (!isTextSection)
    {
        printf("No .text section found!\n");
        return 0;
    }



    // Now lets add a section. for that we need to first create it. We have already statically declared its header above. its calld 'stubSectionHeader'.
    // Our first step will be finding a location for our new section to fit in
    // Lets find the last PT_LOAD program header
    int lastPtLoadIndex;
    lastPtLoadIndex = -1;
    for (i = 0; i < header->e_phnum; i++)
    {
        if (phdr[i]->p_type == PT_LOAD && phdr[i]->p_paddr + phdr[i]->p_filesz + LOADER_SIZE < phdr[i + 1]->p_paddr && phdr[i]->p_vaddr + phdr[i]->p_memsz + LOADER_SIZE < phdr[i + 1]->p_vaddr)
        {
            lastPtLoadIndex = i;
            break;
        }
    }
    // Pointer to the last ptLoad program header
    Elf64_Phdr* ptLoad = phdr[lastPtLoadIndex];
    int lastSectionIndex;
    int j = 0;
    lastSectionIndex = -1;
    for (i = 0; i < header->e_shnum; i++)
    {
        if (shdr[i]->sh_addr + shdr[i]->sh_size >= ptLoad->p_vaddr + ptLoad->p_memsz)
        {

            lastSectionIndex = i + 1;
            printf("new section index: %d\n", lastSectionIndex);
            break;
        }
    }
    if (lastSectionIndex == -1)
    {
        printf("Cant find last section in the PT_LOAD segment\n");
        return 0;
    }


    // Now we need to create the new section and insert it into the array
    // Increase the sections number in the ELF header by 1
    header->e_shnum += 1;

    // Create a new array of section headers
    Elf64_Shdr* newShdr[header->e_shnum];

    // Allocate memory for the new array
    for (i = 0; i < header->e_shnum; i++) newShdr[i] = (Elf64_Shdr*)malloc(header->e_shentsize);

    // Copy shdr[0] - shdr[lastSectionIndex - 1] into newShdr[0] - newShdr[lastSectionIndex - 1]
    for (i = 0; i < lastSectionIndex; i++)
    {
        memcpy(newShdr[i], shdr[i], header->e_shentsize);
    }
    // Copy stubSectionHeader into newShdr[lastSectionIndex]
    memcpy(newShdr[lastSectionIndex], &stubSectionHeader, header->e_shentsize);
    // Copy shdr[lastSectionIndex] - shdr[header->shnum - 2] into newShdr[lastSectionIndex + 1] - newShdr[header->shnum - 1]
    for (i = lastSectionIndex + 1; i < header->e_shnum; i++)
    {
        memcpy(newShdr[i], shdr[i - 1], header->e_shentsize);
    }

    newShdr[lastSectionIndex]->sh_size = LOADER_SIZE;
    newShdr[lastSectionIndex]->sh_offset = newShdr[lastSectionIndex - 1]->sh_offset + newShdr[lastSectionIndex - 1]->sh_size;
    newShdr[lastSectionIndex]->sh_addr = newShdr[lastSectionIndex - 1]->sh_addr + newShdr[lastSectionIndex - 1]->sh_size;

    // Find the start of the sections in the mapping
    char* mySections;
    int startOfSectionsOffset, endOfSectionsOffset, sizeOfSections, lastSectionOffset, difference;
    startOfSectionsOffset = header->e_phoff + header->e_phnum * header->e_phentsize;
    endOfSectionsOffset = header->e_shoff;
    sizeOfSections = endOfSectionsOffset - startOfSectionsOffset;
    lastSectionOffset = shdr[lastSectionIndex]->sh_offset;
    difference = newShdr[lastSectionIndex]->sh_offset - startOfSectionsOffset;
    mySections = (char*)malloc(sizeOfSections);
    memcpy(mySections, p + startOfSectionsOffset, sizeOfSections);


    // Increase the index of the last section in the last PT_LOAD segment by 1
    lastSectionIndex += 1;

    // Lets edit the ptLoad program header so we can fit another section in it
    ptLoad->p_memsz += LOADER_SIZE;
    ptLoad->p_filesz += LOADER_SIZE;

    // Set the flags of the PT_LOAD program header to READ, WRITE, EXECUTE so we can WRITE the decrypted code in it (maybe we shouldn't use mprotect in the stub function because we are already doing the same thing here???)
    for (i = 0; i < header->e_phnum; i++)
    {
        if(phdr[i]->p_type == PT_LOAD)
        {
            phdr[i]->p_flags = PF_X | PF_W | PF_R;
        }
    }

    if (header->e_shstrndx >= lastSectionIndex) {
        header->e_shstrndx += 1;
    }

    for (i = 0; i < header->e_shnum; i++)
    {
        if (newShdr[i]->sh_link >= lastSectionIndex) newShdr[i]->sh_link += 1;
    }
    for (i = 0; i < header->e_shnum; i++)
    {
        if (newShdr[i]->sh_info >= lastSectionIndex) newShdr[i]->sh_info += 1;
    }

    // Start placing the addresses in the shellcode
    char* newShellCode = (char*)malloc(LOADER_SIZE);
    memcpy(newShellCode, myShellCode, LOADER_SIZE);
    char* g;
    g = (char*)newShellCode + 144;
    char* addressToCopy;
    addressToCopy = (char*)shdr[textSectionIndex]->sh_addr;
    memcpy(g, &addressToCopy, sizeof(long int));
    addressToCopy = (char*)shdr[textSectionIndex]->sh_size;
    g = newShellCode + 152;
    memcpy(g, &addressToCopy, sizeof(long int));
    g = newShellCode + 160;
    memcpy(g, &(header->e_entry), sizeof(header->e_entry));

    // Fix the offset of the Section Header Table in the ELF header
    header->e_entry = newShdr[lastSectionIndex - 1]->sh_addr;

    // Continue placing the addresses in the shellcode
    g = newShellCode + 168;
    memcpy(g, &(header->e_entry), sizeof(header->e_entry));

    // Fill in the gap we created earlier
    char* mySectionsPointer = mySections + difference;
    memcpy(mySectionsPointer, newShellCode, LOADER_SIZE);

    FILE* outFile;
    outFile = fopen("/home/roy/lolol", "wb");
    fwrite(header, header->e_ehsize, 1, outFile);
    for (i = 0; i < header->e_phnum; i++)
    {
        fwrite(phdr[i], header->e_phentsize, 1, outFile);
    }
    fwrite(mySections, sizeOfSections, 1, outFile);
    for (i = 0; i < header->e_shnum; i++)
    {
        fwrite(newShdr[i], header->e_shentsize, 1, outFile);
    }
    //fwrite(lastPart, sizeOfLastPart, 1, outFile);


}

int main()
{
    const char* file = "/home/roy/regular";
    encryptFile(file);
    return 0;
}

// TODO AT SUNDAY
// COMPARE THE TEXT SECTIONS IN 'FLAG' AND 'LOLOL' AND TRY TO FIND ANY DIFFERENCE BETWEEN THEM
// *NOTE: REMEMBER THAT THE SHELLCODE IS 0X10 BIGGER BECAUSE YOU TRIED TO XOR EVERY REGISTER. MAKE SURE YOU USE THE COMMENTED SHELCODE AND CHANGE 'LOADER_SIZE' BACK TO 0X70 IF YOU WANT TO USE THE PREVIOUS SHELLCODE (WITHOUT THE XORS)