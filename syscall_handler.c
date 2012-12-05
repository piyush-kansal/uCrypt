#include "decl.h"

// Global Variable Declaration
// Stores the debug messages
__thread char debug_msg_buf[MAX_LOG_MSG_LEN];

// Remembers the file encryption flag across call to syscall_handler_pre() and syscall_handler_post()
int eFlag;

// Function defination to store the password
int storePassword( int iPFile, char *iFName, char *iUser, char *iInodeNo, char *oPass, unsigned int kSize ) {
	GnomeKeyringResult res;
	char *desc, descFmt[] = "File encryption password for User:", descFmt2[] = "for File:", *pass;
	int len, status;
	unsigned int byteCount;

	// Calculate the length of the description. This description is the one which user sees in the Keyring
	len = strlen( descFmt ) + strlen( iUser ) + 1 + strlen( descFmt2 ) + strlen( iFName ) + 1;
	desc = (char *)malloc( sizeof( char ) * len );

	// Lock the desc
	if( mlock( desc, len ) ) {
		byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "STR-PASS: mlock() Failed for desc\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		return -1;
	}

	// Initialize desc with appropriate values
	sprintf( desc, "%s%s %s%s", descFmt, iUser, descFmt2, iFName );

	pass = (char *)malloc( sizeof( char ) * kSize );

	// Lock the pass
	if( mlock( pass, kSize ) ) {
		byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "STR-PASS: mlock() Failed for pass\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		return -1;
	}

	// Pad the pass buffer and then initialize the appropriate values. This is done so that the password
	// length is always equal to as defined by the IV's length requirements of an algorithm
	memset( pass, PAD_CHAR, kSize );
	pass[ kSize - 1 ] = NULL_CHAR;
	sprintf( pass, "%s%s", iUser, iInodeNo );
	pass[ strlen( pass) ] = PAD_CHAR;

	#ifdef _DEBUG_
	byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "Description: %s, Pass: %s\n", desc, pass );
	syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
	#endif

	// Using the GNOME Keyring API, store the password in the Keyring
	res = gnome_keyring_store_password_sync (	&my_schema,
							NULL,
							desc,
							pass,
							"User", iUser,
							"Inode No", iInodeNo,
							NULL);

	// Check results
	if ( res == GNOME_KEYRING_RESULT_OK ) {
		strcpy( oPass, pass );
		status = 0;

		#ifdef _DEBUG_
		byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN, "Password stored successfully\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		#endif
	}
	else {
		byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN, "Error storing password: %s\n", gnome_keyring_result_to_message( res ) );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		status = -1;
	}

	// Unlock the desc and free its memory
	if( munlock( desc, len ) ) {
		byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "STR-PASS: munlock() Failed for desc\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
	}

	free( desc );
	desc = NULL;

	// Unlock the pass and free its memory
	if( munlock( pass, kSize ) ) {
		byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "STR-PASS: munlock() Failed for pass\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
	}

	free( pass );
	pass = NULL;

	return status;
}

// Function defination to find the password
int findPassword( int iPFile, char *iUser, char *iInodeNo, char *oPass, int iKeySize ) {
	GnomeKeyringResult res;
	int status;
	unsigned int byteCount;
	char *temp = (char *)malloc( sizeof( char) * iKeySize );

	// Lock the temp
	if( mlock( temp, iKeySize ) ) {
		byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "FND-PASS: mlock() Failed for temp\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		return -1;
	}

	// This is done because when pass is not found in the keyring, then temp will be set to NULL. Saving
	// the memory location pointed to by temp in temp2 will help us in freeing the memory
	char *temp2 = temp;

	// Pad the temp buffer and then search it in keyring. This is done so that the password
	// length is always equal to as defined by the IV's length requirements of an algorithm
	memset( temp, PAD_CHAR, iKeySize );
	temp[ iKeySize - 1 ] = NULL_CHAR;

	// Using the GNOME Keyring API, find the password in the Keyring
	res = gnome_keyring_find_password_sync (	&my_schema,
							&temp,
							"User", iUser,
                       	                                "Inode No", iInodeNo,
							NULL);

	// Check results
	if ( res == GNOME_KEYRING_RESULT_OK ) {
		strcpy( oPass, temp );
		status = 0;

		#ifdef _DEBUG_
		byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN, "Password found is: %s\n", oPass );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		#endif
	}
	else {
		byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN, "Error finding password: %s\n", gnome_keyring_result_to_message( res ) );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
		status = -1;
	}

	// Unlock the temp and free its memory
	if( munlock( temp2, iKeySize ) ) {
		byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "FND-PASS: mlock() Failed for temp2\n" );
		syscall( SYS_write, iPFile, debug_msg_buf, byteCount );
	}

	free( temp2 );
	temp = NULL;

	return status;
}

// This function is called right before the system call is actually made
void syscall_handler_pre( unsigned int *eax_ptr, unsigned int *ebx_ptr, unsigned int *ecx_ptr, unsigned int *edx_ptr, unsigned int *esi_ptr, unsigned int *edi_ptr) {
	unsigned int byteCount, pFile, k, keysize, fSize, inodeLen, ivSize;
	char *user = NULL, *pass = NULL, *inode = NULL;
	struct stat fs;
	MCRYPT td;

	pFile = syscall( SYS_open, FILE_NAME, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IROTH );
	if ( pFile > 0 ) {
		switch ( *eax_ptr ) {
			case SYS_open:
				#ifdef _DEBUG_
				byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
							"PRE-OPEN-BFR: eFlag is %d, FLAG is %d, Mode is %o\n", eFlag, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				// 1. Since we dont have a descriptor of file being opened as of now, so we are setting an eFlag
				//    variable to 1 just to remember that the current file has been requested to be opened in encryped mode
				// 2. Remove the ENCRYPTION FLAG from the I/P flags
				// 3. Mask the permissions of the file so that user does not set wrong permissions
				if (( ENCRYPTION_MASK & (*ecx_ptr) ) == O_ECRYPT) {
					eFlag = 1;
					*ecx_ptr -= O_ECRYPT;
					*edx_ptr &= PERMISSIONS_MASK;
				}

				#ifdef _DEBUG_
				byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
							"PRE-OPEN-AFR: eFlag is %d, FLAG is %d, Mode is %o\n", eFlag, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				break;

			case SYS_read:
				#ifdef _DEBUG_
				byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
							"PRE-READ: Params :: %u %u %u\n", *ebx_ptr, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				break;

			case SYS_write:
				#ifdef _DEBUG_
				byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
							"PRE-WRITE: Params :: %u %u %u\n", *ebx_ptr, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				if ( processFdFlags[ *ebx_ptr ].encryptFlag ) {
					// If the file pointer is already pointing to the EOF or beyond that then we should
					// allocate more memory. The overall memory size should be equal to the existing one
					// plus the requested one
					if( ( processFdFlags[ *ebx_ptr ].curFP + *edx_ptr ) > processFdFlags[ *ebx_ptr ].fileSize ) {
						fSize = processFdFlags[ *ebx_ptr ].curFP + *edx_ptr;
						processFdFlags[ *ebx_ptr ].fileSize = fSize;
						processFdFlags[ *ebx_ptr ].fileData = ( char * )realloc( processFdFlags[ *ebx_ptr ].fileData, sizeof( char ) * ( fSize + 1 ) );
						memset( processFdFlags[ *ebx_ptr ].fileData, NULL_CHAR, fSize );

						// Also, lock the new buffer. There is no need to unlock the previous buffer
						// as a single call to munlock in the end will itself take care of it
						if( mlock( processFdFlags[ *ebx_ptr ].fileData, fSize + 1 ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-WRITE: mlock() Failed\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}
					}

					switch ( processFdFlags[ *ebx_ptr ].modeFlag ) {
						// If the flag was set as Read Write or Write only then handling will be same
						case O_RDWR:
						case O_WRONLY:
							#ifdef _DEBUG_
							byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
										"PRE-WRITE: Params :: %d %d %d\n",
										processFdFlags[ *ebx_ptr ].curFP,
										processFdFlags[ *ebx_ptr ].fileSize,
										*edx_ptr );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							#endif

							strncpy( ( processFdFlags[ *ebx_ptr ].fileData ) + processFdFlags[ *ebx_ptr ].curFP, ( char * )(*ecx_ptr), *edx_ptr );
							processFdFlags[ *ebx_ptr ].curFP += *edx_ptr;
						
							break;

						// If the flag was set as Read only then we dont need to take care of this as
						// the system call itself will return -1
						case O_RDONLY:
							break;

						// If the flag was set to anything else like an invalid combination of valid
						// flags, then it is an invalid operator and should do nothing
						default:
							break;
					}
				}

				break;

			case SYS_close:
				#ifdef _DEBUG_
				byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
							"PRE-CLOSE: fd :: %u, fileData is::%s::\n", *ebx_ptr, (char *)( ( processFdFlags[ *ebx_ptr ] ).fileData ) );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				if ( processFdFlags[ *ebx_ptr ].encryptFlag ) {
					if( ( processFdFlags[ *ebx_ptr ].modeFlag == O_WRONLY ) || ( processFdFlags[ *ebx_ptr ].modeFlag == O_RDWR ) ) {
						// Get the current user's username
						user = (char *)malloc( sizeof( char ) * ( strlen( getlogin() ) + 1 ) );

						// Lock the user
						if( mlock( user, strlen( getlogin() ) + 1 ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: mlock() Failed for user\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						strcpy( user, getlogin() );

						// Find the inode no for the given file descriptor
						if ( fstat( *ebx_ptr, &fs ) ) {
							byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
										"PRE-CLOSE: Error during fstat for fd :: %u\n", *ebx_ptr );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						// inodeLen is actual length plus 1 to accomodate NULL character
						inodeLen = floor( log10( fs.st_ino ) ) + 1 + 1;
						inode = ( char * )malloc( sizeof( char ) * inodeLen );

						// Lock the inode
						if( mlock( inode, inodeLen ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: mlock() Failed for inode\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						sprintf( inode, "%lu", fs.st_ino );

						// Set the encryption algorithm
						td = mcrypt_module_open( ENCRYPT_ALGO, NULL, CIPHER, NULL );
						if( td == MCRYPT_FAILED ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: mcrypt_module_open() Failed\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						// Find out the IV size
						ivSize = mcrypt_enc_get_iv_size( td ) + 1;

						// Calculate keysize based on length of user name, file inode no
						keysize = strlen( user ) + inodeLen;

						// Allocate memory for pass
						if( ivSize > keysize )
							keysize = ivSize;

						// Allocate memory for pass
						pass = (char *)malloc( sizeof( char ) * keysize );

						// Lock the password
						if( mlock( pass, keysize ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: mlock() Failed for pass\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						// Find if the password is already stored in keyring
						if( findPassword( pFile, user, inode, pass, keysize ) ) {
							if( storePassword( pFile, processFdFlags[ *ebx_ptr ].fileName, user, inode, pass, keysize ) )
								return;
						}

						// Initialize it
						k = mcrypt_generic_init( td, pass, keysize, pass );
						if ( k < 0 ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: mcrypt_generic_init() Failed\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						// Encrypt each character one by one
						k = 0;
						while ( k < processFdFlags[ *ebx_ptr ].fileSize ) {
							mcrypt_generic( td, &( ( processFdFlags[ *ebx_ptr ] ).fileData[ k ] ), 1 );
							k++;
						}

						// Deinit the encryption thread and unload the module
						mcrypt_generic_deinit( td );
						mcrypt_module_close( td );

						#ifdef _DEBUG_
						byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
									"PRE-CLOSE-: fileData is::%s::\n", (char *)( ( processFdFlags[ *ebx_ptr ] ).fileData ) );
						syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						#endif

						syscall( SYS_lseek, *ebx_ptr, 0, SEEK_SET );
						syscall( SYS_write, *ebx_ptr, processFdFlags[ *ebx_ptr ].fileData, processFdFlags[ *ebx_ptr ].fileSize );

						// Unlock memory pages of password
						if( munlock( pass, keysize ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: munlock() Failed for pass\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						free( pass );
						pass = NULL;

						// Unlock the user
						if( munlock( user, strlen( getlogin() ) + 1 ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: munlock() Failed for user\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						free( user );
						user = NULL;

						// Unlock the inode
						if( munlock( inode, inodeLen ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "PRE-CLOSE: munlock() Failed for inode\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						free( inode );
						inode = NULL;
					}
				}

				break;

			default:
				break;
		}
	}

	syscall( SYS_close, pFile );
}

// This function is called right after the function call is made
void syscall_handler_post( unsigned int syscall_no, unsigned int *eax_ptr, unsigned int *ebx_ptr, unsigned int *ecx_ptr, unsigned int *edx_ptr, unsigned int *esi_ptr, unsigned int *edi_ptr) {
	unsigned int fSize = 0, byteCount, pFile, pFile2, ret, k, keysize, inodeLen, ivSize;
	char *user = NULL, *pass = NULL, *inode = NULL;
	struct stat fs;
	MCRYPT td;

	pFile = syscall( SYS_open, FILE_NAME, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IROTH );
	if ( pFile > 0 ) {
		switch ( syscall_no ) {
			case SYS_open:
				#ifdef _DEBUG_
				byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: Params :: %u %u %u %u\n", *eax_ptr, *ebx_ptr, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				// As soon as the open call finishes successfully check if the same file was requested to be opened
				// in encrypted mode. If yes, set the encryption flag of the descriptor returned by open() to 1 in a
				// global array which stores it for all files opened
				// Also, reset the eFlag to 0 so that it can be reused futher for a different file.
				if( eFlag ) {
					// Set values per file descriptor
					processFdFlags[ *eax_ptr ].encryptFlag = eFlag;
					eFlag = 0;

					// Set the file name
					processFdFlags[ *eax_ptr ].fileName = (char *)malloc( sizeof( char ) * ( strlen( (char *)*ebx_ptr ) + 1 ) );
					strcpy( processFdFlags[ *eax_ptr ].fileName, (char *)*ebx_ptr );
					
					// Set the flags
					processFdFlags[ *eax_ptr ].modeFlag = *ecx_ptr & O_CREAT_MASK;

					// Get the file size and then reset the file pointer
					fSize = syscall( SYS_lseek, *eax_ptr, 0, SEEK_END );
					syscall( SYS_lseek, *eax_ptr, 0, SEEK_SET );

					if( fSize < 0 ) {
						return;
					}

					// Set the file size
					processFdFlags[ *eax_ptr ].fileSize = fSize;

					// Allocate the required amount of memory
					processFdFlags[ *eax_ptr ].fileData = ( char * )malloc( sizeof( char ) * ( fSize + 1 ) );

					// Lock the memory for security purpose
					if( mlock( processFdFlags[ *eax_ptr ].fileData, fSize + 1 ) ) {
						byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: mlock() Failed\n" );
						syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						return;
					}

					memset( processFdFlags[ *eax_ptr ].fileData, NULL_CHAR, fSize );

					// If the file size is not 0, then that means there is encrypted data in the file which
					// has to be stored in a buffer in decrypted format
					if( fSize ) {
						// 1. Read the encrypted data from the file in a buffer. But, if the file was opened
						//    in Write only mode, then reading data from it will give error. To handle this
						//    scenario, read it using a different descriptor
						if( O_WRONLY == processFdFlags[ *eax_ptr ].modeFlag ) {
							pFile2 = syscall( SYS_open, *ebx_ptr, O_RDONLY );
							if( pFile2 < 0 ) {
								byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "Error opening file %s\n", (char *)*ebx_ptr );
								syscall( SYS_write, pFile, debug_msg_buf, byteCount );
								return;
							}

							ret = syscall( SYS_read, pFile2, ( void * )( ( processFdFlags[ *eax_ptr ] ).fileData ), fSize );
							syscall( SYS_close, pFile2 );
						}
						else {
							ret = syscall( SYS_read, *eax_ptr, ( void * )( ( processFdFlags[ *eax_ptr ] ).fileData ), fSize );
						}

						#ifdef _DEBUG_
						byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
									"POST-OPEN: fSize::%d:: ret::%d:: fileData::%s::\n",
									fSize, ret, (char *)( ( processFdFlags[ *eax_ptr ] ).fileData ) );
						syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						#endif

						if( -1 == ret )
							return;

						// Get the current user's username
						user = (char *)malloc( sizeof( char ) * ( strlen( getlogin() ) + 1 ) );

						// Lock the user
						if( mlock( user, strlen( getlogin() ) + 1 ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: mlock() Failed for user\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						strcpy( user, getlogin() );

						// Find the inode no for the given file descriptor
						if ( fstat( *eax_ptr, &fs ) ) {
							byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
										"POST_OPEN: Error during fstat for fd :: %u\n", *eax_ptr );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						// inodeLen is actual length plus 1 to accomodate NULL character
						inodeLen = floor( log10( fs.st_ino ) ) + 1 + 1;
						inode = ( char * )malloc( sizeof( char ) * inodeLen );

						// Lock the inode
						if( mlock( inode, inodeLen ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: mlock() Failed for inode\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						sprintf( inode, "%lu", fs.st_ino );

						// Set the encryption algorithm
						td = mcrypt_module_open( ENCRYPT_ALGO, NULL, CIPHER, NULL );
						if( td == MCRYPT_FAILED ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: mcrypt_module_open() Failed\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						// Find out the IV size
						ivSize = mcrypt_enc_get_iv_size( td ) + 1;

						// Calculate keysize based on length of user name, file inode no
						keysize = strlen( user ) + inodeLen;

						// Allocate memory for pass
						if( ivSize > keysize )
							keysize = ivSize;

						pass = (char *)malloc( sizeof( char ) * keysize );

						// Lock the password
						if( mlock( pass, keysize ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST_OPEN: mlock() Failed for pass\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						// Find if the password is already stored in keyring
						if( findPassword( pFile, user, inode, pass, keysize ) ) {
							if( storePassword( pFile, processFdFlags[ *eax_ptr ].fileName, user, inode, pass, keysize ) )
								return;
						}

						#ifdef _DEBUG_
						byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST_OPEN: Pass:%s\n", pass );
						syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						#endif

						// Initiate the encryption algorithm
						k = mcrypt_generic_init( td, pass, keysize, pass );
						if ( k < 0 ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: mcrypt_generic_init() Failed\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							return;
						}

						// Decrypt each character of the file
						k = 0;
						while ( k < fSize ) {
							mdecrypt_generic( td, &( ( processFdFlags[ *eax_ptr ] ).fileData[ k ] ), 1 );
							k++;
						}

						// 4. Deinit the encryption thread and unload the module
						mcrypt_generic_deinit( td );
						mcrypt_module_close( td );

						// Unlock memory pages of password
						if( munlock( pass, keysize ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: munlock() Failed for pass\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						free( pass );
						pass = NULL;

						// Unlock the user
						if( munlock( user, strlen( getlogin() ) + 1 ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: munlock() Failed for user\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						free( user );
						user = NULL;

						// Unlock the inode
						if( munlock( inode, inodeLen ) ) {
							byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-OPEN: munlock() Failed for inode\n" );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						}

						free( inode );
						inode = NULL;
					}

					processFdFlags[ *eax_ptr ].curFP = 0;
				}

				#ifdef _DEBUG_
				byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
							"POST-OPEN: processFdFlags[%d].fileData::%s::\n", *eax_ptr, processFdFlags[ *eax_ptr ].fileData );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				break;

			case SYS_read:
				if ( processFdFlags[ *ebx_ptr ].encryptFlag ) {
					// If the file pointer is already pointing to the EOF or beyond that then we should not
					// read or write anything
					if( processFdFlags[ *ebx_ptr ].curFP >= processFdFlags[ *ebx_ptr ].fileSize )
						return;

					switch ( processFdFlags[ *ebx_ptr ].modeFlag ) {
						// If the flag was set as Read Write or Read only then handling will be same
						case O_RDWR:
						case O_RDONLY:
							if( ( processFdFlags[ *ebx_ptr ].curFP + *edx_ptr ) > processFdFlags[ *ebx_ptr ].fileSize ) {
								strncpy( 	( char * )(*ecx_ptr),
										( processFdFlags[ *ebx_ptr ].fileData ) + processFdFlags[ *ebx_ptr ].curFP,
										processFdFlags[ *ebx_ptr ].fileSize - processFdFlags[ *ebx_ptr ].curFP );
								*eax_ptr = processFdFlags[ *ebx_ptr ].fileSize - processFdFlags[ *ebx_ptr ].curFP;
								processFdFlags[ *ebx_ptr ].curFP += ( processFdFlags[ *ebx_ptr ].fileSize - processFdFlags[ *ebx_ptr ].curFP );
							}
							else {
								strncpy( 	( char * )(*ecx_ptr),
										( processFdFlags[ *ebx_ptr ].fileData ) + processFdFlags[ *ebx_ptr ].curFP, *edx_ptr );
								*eax_ptr = *edx_ptr;
								processFdFlags[ *ebx_ptr ].curFP += *edx_ptr;
							}
						
							#ifdef _DEBUG_
							byteCount = snprintf( 	debug_msg_buf, MAX_LOG_MSG_LEN,
										"POST-READ: Params::%u %u %u %u %u %u\n",
										*eax_ptr, *ebx_ptr, *ecx_ptr, *edx_ptr,
										processFdFlags[ *ebx_ptr ].curFP, processFdFlags[ *ebx_ptr ].fileSize );
							syscall( SYS_write, pFile, debug_msg_buf, byteCount );
							#endif

							break;

						// If the flag was set as Write only then we dont need to take care of this as
						// the system call itself will return -1
						case O_WRONLY:
							break;

						// If the flag was set to anything else like an invalid combination of valid
						// flags, then it is an invalid operator and should do nothing
						default:
							break;
					}
				} else {
/*
					i = 0;
					do {
						#ifdef _DEBUG_
						byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "%c", *(((char *)(*ecx_ptr))+i) );
						syscall( SYS_write, pFile, debug_msg_buf, byteCount );
						#endif
					} while ( ++i < *edx_ptr );
*/
					#ifdef _DEBUG_
					byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "\nREGULAR\n" );
					syscall( SYS_write, pFile, debug_msg_buf, byteCount );
					#endif
				}

				break;

			case SYS_write:
				#ifdef _DEBUG_
				byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-WRITE: Params :: %u %u %u %u\n", *eax_ptr, *ebx_ptr, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				break;

			case SYS_close:
				if ( processFdFlags[ *ebx_ptr ].encryptFlag ) {
					processFdFlags[ *ebx_ptr ].encryptFlag = 0;
					processFdFlags[ *ebx_ptr ].curFP = 0;

					if( munlock( processFdFlags[ *ebx_ptr ].fileData, processFdFlags[ *ebx_ptr ].fileSize + 1 ) ) {
						byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-CLOSE: munlock() Failed\n" );
						syscall( SYS_write, pFile, debug_msg_buf, byteCount );
					}

					free( processFdFlags[ *ebx_ptr ].fileData );
					free( processFdFlags[ *ebx_ptr ].fileName );
					processFdFlags[ *ebx_ptr ].fileData = NULL;
					processFdFlags[ *ebx_ptr ].fileSize = 0;
				}

				#ifdef _DEBUG_
				byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-CLOSE: Params :: %u %u\n", *eax_ptr, *ebx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				break;

			case SYS_lseek:
				if ( processFdFlags[ *ebx_ptr ].encryptFlag ) {
					processFdFlags[ *ebx_ptr ].curFP = *eax_ptr;
				}

				#ifdef _DEBUG_
				byteCount = snprintf( debug_msg_buf, MAX_LOG_MSG_LEN, "POST-LSEEK: Params :: %u %u %u %u\n", *eax_ptr, *ebx_ptr, *ecx_ptr, *edx_ptr );
				syscall( SYS_write, pFile, debug_msg_buf, byteCount );
				#endif

				break;

			default:
				break;
		}
	}

	syscall( SYS_close, pFile );
}
