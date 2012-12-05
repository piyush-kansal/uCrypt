#include <errno.h>
#include "syscall_handler.h"

/***
 * enter_flag: state the status
 * 0 : not being intercepted
 * 1 : inside the interception, right before making the system call
 * 2 : making the system call
 * 3 : inside the interception, right after making the system call
 *
 * You may use libc functions inside the intercepted library.
 * enter_flag is used to make distinguish the two cases such that
 * functions made inside the intercepted library won't be
 * intercepted again.
 **/
__thread int enter_flag = 0;


/***
 * It is important not to mess up the errno
 * Save it before our interception, restore it before returning
 * from our interception.
 **/
__thread int saved_errno = 0;

/***
 * To save the syscall number, so that we can use it in the
 * func_exit. eax, which originally stores the syscall no, will
 * be replaced by the return value of the syscall.
 **/
__thread int syscall_no = 0;

/***
 * func_enter - entry point, syscall will be made afterward
 * Important: Do Not Modify the function signature. It is hardcoded
 * into the intercepted library.
 **/
void func_enter( unsigned int edi, unsigned int esi, unsigned int bp, unsigned int sp, unsigned int ebx, unsigned int edx, unsigned int ecx, unsigned int eax ) {
	// If any file handling primitive is called for any of the STDIN/STDOUT/STDERR descriptors, then do not intercept them
	if( ( 0 == ebx ) || ( 1 == ebx ) || ( 2 == ebx ) )
		return;

	if( enter_flag == 0 ) {
		saved_errno = errno;
		enter_flag = 1;
		syscall_handler_pre( &eax, &ebx, &ecx, &edx, &esi, &edi );
		syscall_no = eax;
		enter_flag = 2;
	}

	return;
}

/***
 * func_exit - exit point, syscall already made
 * Important: Do Not Modify the function signature. It is hardcoded
 * into the intercepted library.
 **/
void func_exit( unsigned int edi, unsigned int esi, unsigned int bp, unsigned int sp, unsigned int ebx, unsigned int edx, unsigned int ecx, unsigned int eax ) {
	if ( enter_flag == 2 ) {
		enter_flag = 3;
		syscall_handler_post( syscall_no, &eax, &ebx, &ecx, &edx, &esi, &edi );
		enter_flag = 0;
		errno = saved_errno;
	}

	return;
}
