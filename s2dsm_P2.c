
#define _GNU_SOURCE

#include <linux/userfaultfd.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#define BUFF_SIZE 4096
#define PAGESIZE sysconf(_SC_PAGE_SIZE)

int remote_socket, new_socket;

static const int read_op = 1;
static const int invalid_op = 2;

unsigned long memory_size, memory_pages;
char *base_addr;

enum state {M, S, I};
enum state *msi_array;

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);	\
	} while (0)

static inline void skip_returnvalue(){}

static void *fault_handler_thread(void *arg){

	static struct uffd_msg msg;
	long uffd;            
	static char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;

	uffd = (long) arg;

	if (page == NULL) {
		page = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			errExit("mmap");
	}


	for (;;) {

		struct pollfd pollfd;
		int nready;

		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");
		
		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			printf("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}

		if (nread == -1)
			errExit("read");

		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			fprintf(stderr, "Unexpected event on userfaultfd\n");
			exit(EXIT_FAILURE);
		}

		printf(" [x] PAGEFAULT\n");

		memset(page, '\0', PAGESIZE);

		uffdio_copy.src = (unsigned long) page;
		uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
			~(PAGESIZE - 1);
		uffdio_copy.len = PAGESIZE;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;

		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");
	}
}

char getMSI(enum state x){
	if (x==M)
		return 'M';
	else if (x==S)
		return 'S';
	else
		return 'I';
}

static void *peer_respond(void *arg){
	char peer_buffer[BUFF_SIZE];
	int read_buffer = 0;	
	for(;;){
		memset(peer_buffer, 0 ,BUFF_SIZE);
		read_buffer = read(remote_socket,peer_buffer,BUFF_SIZE);
	
		if(read_buffer < 0){
			errExit("Error Read in peer respond");
		}
		if(read_buffer > 0){
			int query_page = atoi(strtok(peer_buffer," "));
			int query_code = atoi(strtok(NULL," "));
			printf("*** Query Regarding Page: %d, Operation(1. Read, 2. Invalid): %d ***\n",query_page,query_code);
			enum state initial_state = *(msi_array + query_page);

			if (query_code == read_op){
			
				if (initial_state == M){
					memset(peer_buffer,0,BUFF_SIZE);
					char *msg = base_addr + (query_page*PAGESIZE);
					snprintf(peer_buffer,BUFF_SIZE,"%s",msg);
					*(msi_array + query_page) = S;
				}
				else if (initial_state == I){
					int l = 0x0;
					l = query_page*PAGESIZE;
					strncpy(peer_buffer, base_addr + l, PAGESIZE);
					memset(peer_buffer,0,BUFF_SIZE);
					sprintf(peer_buffer,"%s","Invalid Page");
					*(msi_array + query_page) = S;	
				}

			}
			else if (query_code == invalid_op){
				if (madvise(base_addr + (query_page*PAGESIZE), PAGESIZE, MADV_DONTNEED)){
						errExit("fail to madvise");
				}
				*(msi_array + query_page) = I;
				memset(peer_buffer,0,BUFF_SIZE);
				sprintf(peer_buffer,"%s","Successful Invalidation");
			}
			printf("*** Page State was: %c, Responding with message: %s ***\n", getMSI(initial_state),peer_buffer);
			send(remote_socket,peer_buffer,BUFF_SIZE,0);
		}	
	}
}

void initialize_msi_array(){
	enum state *temp = msi_array;
	for(int i = 0; i < (int)memory_pages; i++){
		*temp = I;
		temp++;
	}
}
void print_msi_array(){
	enum state *temp = msi_array;
	for (int i = 0; i <(int)memory_pages; i++){
			printf("[*] Page: %d, MSI State: %c\n",i,getMSI(*temp));
			temp++;
	}
}

char *call_peer(int requested_page, int opcode){

	char *local_buffer = malloc(sizeof(char)*BUFF_SIZE);
	memset(local_buffer,0,BUFF_SIZE);
	sprintf(local_buffer,"%d %d",requested_page, opcode);
	send(new_socket,local_buffer,BUFF_SIZE,0);
	memset(local_buffer,0,BUFF_SIZE);
	if(read(new_socket,local_buffer,BUFF_SIZE) < 0){
		errExit("Error Read");
	}
    return local_buffer;
}

void set_page(int requested_page, char *message, bool write_flag){
	enum state page_state = *(msi_array + requested_page);
	int l = 0x0;

	if (page_state == M){
		l = requested_page*PAGESIZE;
		strcpy(base_addr + l,message);
		printf(" [*] Page %i:\n%s\n",requested_page, base_addr+l);
	}
	else if ((page_state == S) || (page_state == I)){
		l = requested_page*PAGESIZE;
		strcpy(base_addr + l,message);

		if (write_flag){
			printf(" [*] Page %i:\n%s\n",requested_page,base_addr+l);
			*(msi_array + requested_page) = M;
			char *peer_response = call_peer(requested_page,invalid_op);

			if (strcmp(peer_response,"Successful Invalidation")!= 0){
				errExit("Peer Invalidation Error");
			}
			free(peer_response);
		}
	}
}

void write_page(int requested_page, char *message){
	if(requested_page == -1){
		int counter = 0;
		while(counter < (int)memory_pages){
			set_page(counter,message,true);
			counter++;
		}
	}
	else{
		set_page(requested_page,message,true);
	}	
}

void get_page(int requested_page){
	enum state page_state = *(msi_array + requested_page);
	char page_content[BUFF_SIZE] = {0};
	int l = 0x0;
	l = requested_page*PAGESIZE;
	strncpy(page_content, base_addr + l, PAGESIZE);
	

	if (page_state == M){	
		printf(" [*] Page %i:\n%s\n", requested_page, page_content);
	}

	else if (page_state == S){
		if(page_content[0] == '\0'){
			printf(" [*] Page %i:\n%s\n", requested_page, "");
		}
		else{
			printf(" [*] Page %i:\n%s\n", requested_page, page_content);
		}
	}

	else{
		printf("*** Page State is I. Fetching Content From Peer ***\n");
		char *peer_response = call_peer(requested_page, read_op);

		if (strcmp("Invalid Page",peer_response)!=0){
			set_page(requested_page, peer_response, false);
			printf(" [*] Page %i:\n%s\n", requested_page, base_addr + l);
			*(msi_array + requested_page) = S;
		}
		else{
			*(msi_array + requested_page) = S;
			printf(" [*] Page %i:\n%s\n", requested_page, "");
		}
		free(peer_response);
	}	
}


void read_page(int requested_page){
	if(requested_page == -1){
		int counter = 0;
		while(counter < (int)memory_pages){
			get_page(counter);
			counter++;
		}
	}
	else{
		get_page(requested_page);
	}
}


int main(int argc, const char *argv[]){

	int local_socket;
	char *addr, *rest;

	int local_port = atoi(argv[1]);
	int remote_port = atoi(argv[2]);
	int flag = 0;

	struct sockaddr_in local_address, remote_address, cli_addr;
	int opt = 1;
	int addrlen = sizeof(local_address);
	char buffer[BUFF_SIZE] = {0};

	long uffd;      
	pthread_t thr, peer_response_thread;     
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;
	int s, page;
	char instruct;

	
	if ((local_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	if ((remote_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	
	if (setsockopt(local_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
		       &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	local_address.sin_family = AF_INET;
	local_address.sin_addr.s_addr = INADDR_ANY;
	local_address.sin_port = htons(local_port);

	memset(&remote_address, '0', sizeof(remote_address));
	remote_address.sin_family = AF_INET;
	remote_address.sin_port = htons(remote_port);

	if(inet_pton(AF_INET, "127.0.0.1", &remote_address.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}


	if (bind(local_socket, (struct sockaddr *)&local_address, sizeof(local_address)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(local_socket, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}


	if (connect(remote_socket, (struct sockaddr *)&remote_address, sizeof(remote_address)) < 0) {
		printf("Connection Failed\n");
		flag = 1;
	}
	else{
		printf("Connection Accepted\n");
	}
	
	if ((new_socket = accept(local_socket, (struct sockaddr *)&cli_addr,
				 (socklen_t*)&addrlen)) < 0) {
		perror("Accept Failed");
		exit(EXIT_FAILURE);
	}
	else{
		printf("Accept Passed\n");
	}

	if (connect(remote_socket, (struct sockaddr *)&remote_address, sizeof(remote_address)) < 0) {
		printf("Second Connection Failed\n");
	
	}
	else{
		printf("Second Connection Accepted\n");
	}

    //first process
	if (flag){
		
		printf("How many pages would you like to allocate (greater than 0)?\n");
		memset(buffer,0,BUFF_SIZE);
		skip_returnvalue(fgets(buffer,BUFF_SIZE,stdin));

		memory_pages = strtoul(buffer,&rest,10);
		memory_size =  memory_pages * PAGESIZE;

		msi_array = malloc((int)memory_pages);

		addr = mmap(NULL, memory_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED){
			perror("mmap");
			exit(EXIT_FAILURE);
		}
		base_addr = addr;

		printf("Address returned by mmap() in first process = %p\n", addr);
		printf("Size of the mmaped region in first process = %lu\n", memory_size);

		memset(buffer,0,BUFF_SIZE);
		sprintf(buffer,"%p %lu",addr, memory_size);
		send(new_socket, buffer, BUFF_SIZE, 0);
	}

	//second process
	else{
		
		memset(buffer,0,BUFF_SIZE);
		if (read(remote_socket, buffer, BUFF_SIZE) < 0) {
			perror("Error");
			printf("\nRead Failed \n");
			return -1;
    	}
		printf("Message from the first process: %s\n",buffer);

		char *memory_address;

		memory_address = strtok(buffer," ");
		memory_size = strtoul(strtok(NULL," "),&rest,10);
		memory_pages = memory_size/PAGESIZE;

		msi_array = malloc((int)memory_pages);

		sscanf(memory_address,"%p",&addr);

		addr = mmap(addr, memory_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED){
			perror("mmap");
			exit(EXIT_FAILURE);
		}
		base_addr = addr;
		printf("Address returned by mmap() in second process = %p\n", addr);
		printf("Size of the mmaped region in second process = %lu\n", memory_size);

	}

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
		if (uffd == -1)
			errExit("userfaultfd");

		uffdio_api.api = UFFD_API;
		uffdio_api.features = 0;
		if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
			errExit("ioctl-UFFDIO_API");

		uffdio_register.range.start = (unsigned long) addr;
		uffdio_register.range.len = memory_size;
		uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
		if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
			errExit("ioctl-UFFDIO_REGISTER");

		s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
		if (s != 0) {
			errno = s;
			errExit("pthread_create");
		}

		s = pthread_create(&peer_response_thread, NULL, peer_respond, (void *) uffd);
		if (s != 0) {
			errno = s;
			errExit("pthread_create");
		}

		initialize_msi_array();

		for(;;){

			printf("> Which command should I run? (r:read, w:write, v:view msi array):\n");
			memset(buffer,0,BUFF_SIZE);
			skip_returnvalue(fgets(buffer,BUFF_SIZE,stdin));

			instruct = *strtok(buffer," ");
			
			if (instruct == 'v'){
				print_msi_array();
				continue;
			}

			printf("> For which page? (0-%i, or -1 for all)\n",(int)memory_pages-1);
			memset(buffer,0,BUFF_SIZE);
			skip_returnvalue(fgets(buffer,BUFF_SIZE,stdin));
			
			page = atoi(strtok(buffer," "));
		
			if(page >= (int)memory_pages || page < -1){
				printf("Invalid Page Number\n");
				exit(EXIT_FAILURE);
			}

			if(instruct == 'r'){
				read_page(page);
			}
			else{
				printf("> Type your new message: ");
				memset(buffer,0,BUFF_SIZE);
				skip_returnvalue(fgets(buffer,BUFF_SIZE,stdin));
				write_page(page,buffer); 
			}
		} 
	return 0;
}
