#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define O_ECRYPT 00000010

int main() {
	char ip[50] = "name is piyush kansal fall 201", op[50], fName[10];
	int i, fd[5];

	for( i = 0 ; i < 50 ; i++ )
		op[i] = '\0';

	for( i = 0 ; i < 5 ; i++ ) {
		sprintf( fName, "%s%d", "exp6", i);
		fd[i] = open( fName, O_CREAT | O_RDWR | O_ECRYPT, S_IRWXU );
		sprintf( ip, "%s%d", "name is piyush kansal fall 201", i );
		printf( "Bytes write ::%d::\n", write( fd[i], ip, 32 ) );
	}

	for( i = 0 ; i < 5 ; i++ ) {
		close(fd[i]);
	}

	for( i = 0 ; i < 5 ; i++ ) {
		sprintf( fName, "%s%d", "exp6", i);
		fd[i] = open( fName, O_RDONLY | O_ECRYPT );
		printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd[i], op, 32 ) );
	}

	for( i = 0 ; i < 5 ; i++ ) {
		close(fd[i]);
	}

	return 0;
}
