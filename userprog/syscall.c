#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/* For implementation */
#include "threads/init.h" // power_off
#include "threads/vaddr.h" // is_user_vaddr
#include "filesys/filesys.h" // filesys_create
#include "threads/palloc.h" // PAL_ZERO 이런거 쓰려고
#include "userprog/process.h" 

#include "filesys/file.h" // file_read
#include "lib/kernel/console.h" //putbuf


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* system call */
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int filesize(int fd);
int exec(char *file_name);
tid_t fork(const char *thread_name, struct intr_frame *if_);
int open(const char *file);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
int dup2(int oldfd, int newfd);

/* Helper Fuction */
static struct file *find_file_by_fd(int fd);
void remove_file_from_fdt(int fd);
int add_file_to_fdt(struct file *file);

/* extra */
#define STDIN 1
#define STDOUT 2

// file read write lock
struct lock file_rw_lock; 

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init(&file_rw_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		if(exec(f->R.rdi)==-1)
			exit(-1);
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax= filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_DUP2:
		f->R.rax = dup2(f->R.rdi, f->R.rsi);
	default:
		exit(-1);
		break;
	}
}



/****************** System Call Implementations ********************/

void check_address(void *addr){
	struct thread *cur = thread_current();
	/* 
	  user_vaddr이 아닌 경우
	  addr이 0이나 NULL로 오는 경우
	  mapping되지 않은 가상 메모리인 경우
	*/
	if(!is_user_vaddr(addr) || addr == NULL || pml4_get_page(cur->pml4, addr)==NULL){
		exit(-1); 
	}
}


void halt(void){
	power_off();
}

void exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	check_address(file);
	return filesys_remove(file);
}

int exec(char *file_name){
	check_address(file_name);

	int len = strlen(file_name) + 1;
	
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL)
		exit(-1);
	
	strlcpy(fn_copy, file_name, len);

	if(process_exec(fn_copy)==-1){
		return -1;
	}

	NOT_REACHED();
	return 0;
}

tid_t fork(const char *thread_name, struct intr_frame *if_){
	return process_fork(thread_name, if_);
}


int filesize(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

int open(const char *file)
{
	check_address(file);
	struct file *fileobj = filesys_open(file);

	if (fileobj == NULL)
		return -1;

	int fd = add_file_to_fdt(fileobj);

	// FD table full
	if (fd == -1)
		file_close(fileobj);

	return fd;
}


int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	int ret;
	struct thread *cur = thread_current();

	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj==NULL)
		return -1;

	
	if(fileobj == STDIN){
		// extra - 0,1 file descriptor도 닫을 수 있게
		if(cur->stdin_count ==0){
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else{
			int i; 
			unsigned char *buf = buffer;
			for(i=0; i<size; i++){
				char c = input_getc();
				*buf++ = c;
				if(c=='\0')
					break;
			}
			ret = i;
		}
	}
	else if(fileobj==STDOUT){
		ret = -1;
	}
	else{
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
		
	}
	
	return ret;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	
	int ret;
	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj==NULL)
		return -1;
	
	struct thread *cur = thread_current();
	
	if (fileobj==STDOUT){
		if(cur->stdout_count == 0){
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}

		else{
			putbuf(buffer, size); // 
			ret = size;
		}
	}
	else if(fileobj == STDIN){
		ret = -1;
	}
	else{
		lock_acquire(&file_rw_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	
	return ret;
}

void close(int fd){
	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj == NULL)
		return;
	struct thread *cur = thread_current();

	// extra
	if (fd ==0 || fileobj ==STDIN)
		cur->stdin_count--;
	else if(fd==1 || fileobj == STDOUT)
		cur->stdout_count--;
	
	remove_file_from_fdt(fd);
	
	if (fd <= 1 || fileobj <= 2)
		return;

	if (fileobj -> dupCount == 0)
		file_close(fileobj);
	else
		fileobj -> dupCount--;
}

void seek(int fd, unsigned position)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	fileobj->pos = position;	
}

unsigned tell(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	return file_tell(fileobj);
}

int dup2(int oldfd, int newfd){
	struct file *fileobj = find_file_by_fd(oldfd);
	if(fileobj == NULL)
		return -1;
	
	// 위에서 여기로 옮김. edge test case
	if(oldfd == newfd){
		return newfd;
	}
	
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;

	if(fileobj== STDIN)
		cur->stdin_count++;
	else if(fileobj == STDOUT)
		cur->stdout_count++;
	else
		fileobj->dupCount++;
	
	close(newfd);
	fdt[newfd] = fileobj;
	return newfd;
}


/* Helper function */

int add_file_to_fdt(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;	// file descriptor table

	// Project2-extra - (multi-oom) Find open spot from the front
	while (cur->fdIdx < FDCOUNT_LIMIT && fdt[cur->fdIdx])
		cur->fdIdx++;

	// Error - fdt full
	if (cur->fdIdx >= FDCOUNT_LIMIT)
		return -1;

	fdt[cur->fdIdx] = file;
	return cur->fdIdx;
}

static struct file *find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid id
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	
	return cur->fdTable[fd];	// automatically returns NULL if empty
}

void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();
	if(fd<0 || fd>=FDCOUNT_LIMIT)
		return;
	cur->fdTable[fd] = NULL;
}
