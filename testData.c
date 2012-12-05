#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define O_ECRYPT 00000010

int main() {
	char ip[50] = "name is piyush kansal fall 2011", op[69];

	// Test for read only mode and reading from file
	int i, fd = open( "exp4.txt", O_RDONLY | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	lseek( fd, 10, SEEK_SET );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	lseek( fd, -60, SEEK_END );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	close(fd);

	// Test for write only mode and reading from file
	fd = open( "exp4.txt", O_WRONLY | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	lseek( fd, 10, SEEK_SET );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	lseek( fd, -60, SEEK_END );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	close(fd);

	// Test for invalid mode and reading from file
	fd = open( "exp4.txt", O_WRONLY | O_RDWR | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	lseek( fd, 10, SEEK_SET );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	lseek( fd, -60, SEEK_END );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	close(fd);

	// Test for read write mode and reading from file
	fd = open( "exp4.txt", O_RDWR | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	lseek( fd, 10, SEEK_SET );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	lseek( fd, -60, SEEK_END );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	close(fd);

	printf( "Opening 1" );
	fd = open( "exp4.txt", O_WRONLY | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	lseek( fd, 10, SEEK_SET );

	strcpy( op, "Matthews is" );
	printf( "Bytes written ::%d::\n", write( fd, op, 11 ) );

	close(fd);

	printf( "Opening 2" );
	fd = open( "exp4.txt", O_RDONLY | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	close(fd);

	printf( "Opening 3" );
	fd = open( "exp4.txt", O_RDWR | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	lseek( fd, 10, SEEK_SET );

	strcpy( op, "Matt Culver" );
	printf( "Bytes written ::%d::\n", write( fd, op, 11 ) );

	lseek( fd, 0, SEEK_SET );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	lseek( fd, 0, SEEK_SET );
	strcpy( op, "SBU is an e" );
	printf( "Bytes written ::%d::\n", write( fd, op, 11 ) );

	close(fd);

	printf( "Opening 4" );
	fd = open( "exp4.txt", O_RDONLY | O_ECRYPT );

	for( i = 0 ; i < 70 ; i++ )
		op[i] = '\0';

	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );
	printf( "O/P ::%s:: Bytes read ::%d::\n", op, read( fd, op, 10 ) );

	close(fd);

	fd = open( "exp5.txt", O_CREAT | O_RDWR | O_ECRYPT, S_IRWXU | S_IRWXG | S_IRWXO );
	printf( "Bytes write ::%d::\n", write( fd, ip, 31 ) );
	close(fd);

	return 0;
}
