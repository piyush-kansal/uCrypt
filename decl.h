#ifndef __DECL_H__
#define __DECL_H__

// Include required header files
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <mcrypt.h>
#include <linux/fs.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <gnome-keyring-1/gnome-keyring.h>
#include <gnome-keyring-1/gnome-keyring-memory.h>

// Various macros used for processing
#define ENCRYPT_ALGO		"twofish"
#define CIPHER			"cfb"
#define MAX_LOG_MSG_LEN 	1000
#define O_ECRYPT		00000010
#define ENCRYPTION_MASK         00000010
#define O_CREAT_MASK            07777077
#define PERMISSIONS_MASK        07700
#define FILE_NAME               "syscallLog"
//#define _DEBUG_                 1
#define NULL_CHAR               '\0'
#define PAD_CHAR		'Z'

// Declare GNOME Keyring Schema 
GnomeKeyringPasswordSchema my_schema = {
        GNOME_KEYRING_ITEM_GENERIC_SECRET,
        {
                { "User", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
                { "Inode No", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
                { NULL, 0 }
        }
};

// Data Structure for maintaining the state of the file descriptors of user
// Currently the max no of files a user can work with has been set to INR_OPEN
// It can be changes further as per the requirements
struct fDFlags {
        // Describes if the encryption flag is set for the current file descriptor
        int encryptFlag;

        // Describes the other flags passed during call to open() in second argument
        int modeFlag;

        // Contains file name being processed
        char *fileName;

        // Describes file size for the current file descriptor
        int fileSize;

        // Pointer to the decrypted file data in memory. This memory location is further locked to avoid swapping of its pages
        // Locking has been done to enhance the security
        char *fileData;

        // Describes location of file pointer for the current file descriptor
        int curFP;
} processFdFlags[ INR_OPEN ];

#endif /* __DECL_H__ */
 
