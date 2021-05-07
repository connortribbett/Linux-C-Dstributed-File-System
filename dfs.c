#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <signal.h>
#include "dfsys.h"

#include <sys/syscall.h>    // debug
#include <errno.h>          // debug

typedef struct svr_config { // Structure holding DFS server config and valid user/passes
    int  user_count;        // Number of valid users
    short port;             // Port to bind to
    char svr_name[16];      // Server name to identify storage directory
    int len_svr_name;       // Strlen of svr_name
    char users[64][16];     // Array of valid usernames. Corresponding password is in the same index in pwds[]
    char pwds[64][16];
    unsigned char pwd_MD5s[64][MD5_DIGEST_LENGTH];  //MD5 hashes of passwords for quick verification
} svr_config;

typedef struct handler_args { // Structure to pass arguments to handler
    int fd;                   // Connection file descriptor
    svr_config *cfg;          // Pointer to global config (read-only)
} handler_args;

void *handler(void *vargp);
int open_listenfd(int port);
int svr_read_config(char *filename, svr_config *config);
int svr_parse_cmd(char *cmd, dfs_cmd *out, svr_config *cfg, int sz_received);
int svr_run_cmd(dfs_cmd *cmd, char *data, int *cl_fd, svr_config *config);
int verify_user(dfs_cmd *cmd, svr_config *config);

int main(int argc, char **argv)
{
    /*====================================================================================*/
    /*===================================CONFIG PARSING===================================*/
    /*====================================================================================*/
    if(argc != 4){                      // Check argument count
        fprintf(stderr, "Usage: %s <svr name> <port> <config file>\n", argv[0]);
        exit(0);
    }
    signal(SIGPIPE, SIG_IGN);           // Handle SIGPIPE locally if the client prematurely ends the connection
    svr_config cfg;                     // Create config struct to be filled
    memset(&cfg, 0, sizeof(svr_config)); // Zero it out

    strncpy(cfg.svr_name, argv[1], 16); // Save the name

    struct stat svr_dir_stat;                         // If directory of svr_name doesn't exist, create it with read/write perms
    if(stat(cfg.svr_name, &svr_dir_stat) == -1){
        mkdir(cfg.svr_name, 0777);
    }

    cfg.len_svr_name = strlen(cfg.svr_name);          // Save the server name length for later directory parsing

    short port = (unsigned short) atoi(argv[2]); // Convert port argument into a short

    if(port < 1024){                                   // Ensure the port is valid
        fprintf(stderr, "%s is an invalid port. Ensure port is >= 1024\n", argv[2]);
        exit(0);
    }
    cfg.port = port;                                   // Save to the config

    if(svr_read_config(argv[3], &cfg)){        // Parse the config file passed as arg 2 and ensure it is correct
        fprintf(stderr, "Server config file parsing failed. See readme.MD for structure.\n");
        exit(0);
    }

    // Pretty print the config
    //printf("-------------Parsed %d Users------------\n", cfg.user_count);
    //printf("----------------------------------------\n");
    for(int i = 0; i < cfg.user_count; i++){    // When parsing users to print, also create directories for them under server dir
        char userdir[512];                      // Buffer to hold new user directory
        memset(userdir, 0, 512);
        strncpy(userdir, cfg.svr_name, cfg.len_svr_name); // Copy the server name + '/' then username + '/'
        *(userdir + cfg.len_svr_name) = '/';
        strncpy(userdir + cfg.len_svr_name + 1, cfg.users[i], 16);
        int len_user = strlen(cfg.users[i]);
        *(userdir + cfg.len_svr_name + 1 + len_user) = '\0';

        struct stat user_dir_stat;                       // If this user directory doesn't exist, creat it
        if(stat(userdir, &user_dir_stat) == -1){
            mkdir(userdir, 0777); // Make server dir
        }

        //printf("User[%d]: %s\n", i, cfg.users[i]);
        //printf("pass[%d]: %s\n", i, cfg.pwds[i]);
        //printf(" - MD5: ");
        for(int j = 0; j < MD5_DIGEST_LENGTH; j++){
            //printf("%02x", cfg.pwd_MD5s[i][j]);
        }
        //printf("\n");
    }
    //printf("----------------------------------------\n");
    /*====================================================================================*/
    /*===================================Start Listening==================================*/
    /*====================================================================================*/
    int listenfd, *connfdp, clientlen = sizeof(struct sockaddr_in); // Listen socket variables/arguments
    struct sockaddr_in clientaddr;
    pthread_t tid;

    listenfd = open_listenfd(cfg.port);     // Listen on specified port
    //printf("Server (name: %s) listening on port (Host byte order): %d\n", cfg.svr_name, cfg.port);
    while(1){                               // Continually accept connections and spawn handler threads
        handler_args *thread_args = malloc(sizeof(handler_args));
        thread_args->cfg = &cfg;            // Pass config to heap thread_args struct
        thread_args->fd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen); // Accept connection and put FD in thread_args struct
        pthread_create(&tid, NULL, handler, thread_args); // Spawn thread to handle client connection and pass thread_args struct
    }

    return 0;
}

void *handler(void *vargp){
    int connfd = ((handler_args *) vargp)->fd;       // Get connection fd from args struct
    svr_config *cfg = ((handler_args *) vargp)->cfg; // Get config ptr
    pthread_detach(pthread_self());                  // Detach from main()
    free(vargp);                                     // Free the passed argument structure

    struct timeval timeout;         // Set a timeout of 10 seconds on the socket
    timeout.tv_sec = 10;             // For send() and recv()
    timeout.tv_usec = 0;
    setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(struct timeval));
    setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(struct timeval));


    pthread_t tid = syscall(SYS_gettid); // For debug/state printing. This system call will not work on MacOS


    //printf("T(%d):S(%d)- Opened connection, handling...\n", (int)tid, connfd);
    char cmd_buffer[SZ_CMD_BUFF + sizeof(dfs_cmd) + 1];    // Create and zero buffers to receive a command from a client
    dfs_cmd client_cmd;
    memset(cmd_buffer, 0, SZ_CMD_BUFF + sizeof(dfs_cmd) + 1);
    memset(&client_cmd, 0, sizeof(dfs_cmd));

    int sz_received = recv(connfd, cmd_buffer, SZ_CMD_BUFF + sizeof(dfs_cmd), 0); // Attempt to receive a command
    //printf("T(%d):S(%d)- Received command.\n", (int)tid, connfd);
    if(sz_received <= 0){   // If recv() errored or timed out, close the connection and return.
        //printf("T(%d):S(%d)- Failed on receiving command: %d\n", (int)tid, connfd, sz_received);
        close(connfd);
        return NULL;
    }else if(sz_received < sizeof(dfs_cmd)){    // If recv()ed bytes isn't big enough to be a command, end the connection
        //printf("T(%d):S(%d)- Didn't receive enough data to be a command.\n", (int)tid, connfd);
        close(connfd);
        return NULL;
    }

    if(!svr_parse_cmd(cmd_buffer, &client_cmd, cfg, sz_received)){ // Parse the received data into a dfs_cmd structure
        //printf("T(%d):S(%d)- Command was parsed, running...\n", (int)tid, connfd); // If the command was was parsed correctly.
        svr_run_cmd(&client_cmd, cmd_buffer, &connfd, cfg);        // Run the command specified in dfs_cmd
    }else{
        //printf("T(%d):S(%d)- Failed to parse command.\n", (int)tid, connfd);
    }

    //printf("T(%d):S(%d)- Handled connection, exiting thread...\n", (int)tid, connfd);
    close(connfd);                                                 // Connection handled, close connection and return
    return NULL;
}

/*
 *  Takes in received bytes from client, output structure to fill, server config, and # of bytes received
 *  Will parse the bytes received into a command and sanitize the data buffer to only contain command data (if applicable)
 *  Will also verify if the user/pass of the client is valid from the config file.
 *  Returns 0 on success w/ verified user, returns 1 otherwise
 */
int svr_parse_cmd(char *data, dfs_cmd *out, svr_config *cfg, int sz_received){
    memcpy(out, data, sizeof(dfs_cmd)); // Copy what should be the dfs_cmd struct into the output structure
    //printf("Received %d/%d bytes.\n", sz_received, (int)sizeof(dfs_cmd) + (int)out->data_len);
    if(sz_received < sizeof(dfs_cmd) + out->data_len){           // Check if we received the full data from the command
        //printf("Didn't receive full command packet.\n"); // Return an error if we didn't
        return 1;
    }

    if(!verify_user(out, cfg)){                                  // Verify the user in the command with the cfg
        //printf("User verification not valid.\n");
        return 1;                                                // Return error on failure
    }

    if(out->data_len > 0){                                       // If there is data w/ the command, move it in place
        memcpy(data, data + sizeof(dfs_cmd), out->data_len); // Copy out dfs_cmd struct from received data. memcpy is safe these will never overlap
    }

    return 0;
}

/*
 * Takes filled dfs_cmd struct, associated data buffer, client socket FD, and svr config
 * Carries out the specified command with specified data
 */
int svr_run_cmd(dfs_cmd *cl_cmd, char *cl_data, int *cl_fd, svr_config *config){
    char filename[512];                                         // Parse the received filename to the correct svr_dir/user_dir/filename
    memset(filename, 0, 512);
    strncpy(filename, config->svr_name, 16);            // copy svr_name + '/' + user in cmd + '/' + filename(or directory name)
    int pos = config->len_svr_name;
    *(filename + pos) = '/';
    pos++;
    strncpy(filename + pos, cl_cmd->user, 16);
    pos += strlen(cl_cmd->user);
    *(filename + pos) = '/';
    *(filename + pos + 1) = '\0';
    if(cl_cmd->data_len != 0){                                 // If there is a filename supplied, copy it on last
        strncpy(filename + pos + 1, cl_data, 512 - pos - 1);
    }

    switch(cl_cmd->cmd){                                        // Switch to handle received command
        /*====================================================================================*/
        /*=====================================GET COMMAND====================================*/
        /*====================================================================================*/
        case 1:
            ;
            //printf("Received get command with args:%s\n", cl_data);
            FILE *fp = fopen(filename, "rb");                           // Open the request file in the svr/user specific directory (parsed before)
            if (fp){                                                          // If valid, read the block_file from disk and send it.
                //printf("Found file & opened to send.\n");
                block_file fileBlock;
                int bytesGot = fread(&fileBlock, 1, sizeof(block_file), fp);
                send(*cl_fd, &fileBlock, bytesGot, 0);                        // Send file_block, then send whole both parts stored after block file with send_file_tcp()
                send_file_tcp(fp, sizeof(block_file), fileBlock.block_lens[fileBlock.blocks_stored[0]]+fileBlock.block_lens[fileBlock.blocks_stored[1]], 0, *cl_fd);
                fclose(fp);
            }else{                                                            // If the server doesn't have the file, send a block_file of all 00s to signify this
                //printf("File doesn't exist, sending blank block.\n");
                block_file blank_block;
                memset(&blank_block, 0, sizeof(block_file));
                send(*cl_fd, &blank_block, sizeof(block_file), 0);
            }

            //printf("Ended GET command.\n");
            break;
        /*====================================================================================*/
        /*=====================================PUT COMMAND====================================*/
        /*====================================================================================*/
        case 2:;
            //printf("Running PUT command...\n");

            block_file header;                              // block_file buffer to hold info on file to receive
            memset(&header, 0, sizeof(block_file));    // Zero it then receive the block_file form the client
            if(recv(*cl_fd, &header, sizeof(block_file), 0) < sizeof(block_file)) {
                //printf("Recv Failed @ put\n");
                break;
            }
            //printf("Received block_file header for incoming file.\n");

            short block1 = header.blocks_stored[0]; // Extract the blocks that server will be receiving
            short block2 = header.blocks_stored[1];

            //printf("Going to receive blocks (%d,%d).\n", block1, block2);

            if(block1 < 0 || block1 > 3 || block2 < 0 || block2 > 3){  // Make sure they're valid. Break if not.
                //printf("Bad blocks received on PUT.\n");
                break;
            }

            // Calculate the length that must now be received based on the blocks being sent next
            int len_to_recv = header.block_lens[block1] + header.block_lens[block2];
            //printf("Going to receive %d file bytes.\n", len_to_recv);

            FILE *file = fopen(filename, "wb"); // Open the file in the client directory to put the file

            char fileBuffer[SZ_FILE_BUFF];             // Large buffer to hold incoming file bytes
            if(file){                                  // Ensure it's valid
                //printf("File to PUT open, recving and putting...\n");
                fwrite(&header, 1, sizeof(block_file), file); // Write the file_block header to start. Will keep this info at the start for LIST and GET
                //printf("Wrote file_block header\n");
                int bytesLeft = len_to_recv;    // Counter to count down from total bytes to receive

                while(bytesLeft > 0){           // Loop until we have received all bytes
                    //printf("Recv()ing with %d bytes left.\n", bytesLeft);
                    memset(fileBuffer, 0, SZ_FILE_BUFF);
                    // If the server must read bytes >= the size of the buffer, use the full thing
                    // Otherwise just use bytesLeft bytes of it.
                    int toRead = bytesLeft >= SZ_FILE_BUFF ? SZ_FILE_BUFF : bytesLeft;
                    //printf("Going to read: %d bytes\n", toRead);
                    int bytesRead = recv(*cl_fd, fileBuffer, toRead, 0);    // Recv toRead bytes from client
                    if(bytesRead <= 0){                                     // If nothing is being received, break
                        break;
                    }
                    //printf("Read %d bytes.\n", bytesRead);
                    fwrite(fileBuffer, 1, bytesRead, file);      // Write these recv()ed bytes and update the counter
                    bytesLeft -= bytesRead;
                }
                fclose(file);
            }else{                  // If the file is invalid, don't write anything and exit
                //printf("Unable to open file to PUT.\n");
            }

            //printf("Ran put command with args:%s\n", cl_data);
            break;
        /*====================================================================================*/
        /*====================================LIST COMMAND====================================*/
        /*====================================================================================*/
        case 3:
            ;
            block_file dir_block;                           // Block_file set to all 1s. Signifies a directory
            memset(&dir_block, 1, sizeof(block_file));
            block_file file_ls;                             // Block file buffer to send to client
            int namesz;                                     // Integer file/dir name size to sent to client
            char entname[256];                              // file/dir name buffer to send to client
            struct dirent *dent = NULL;                     // dirent to loop through the requested directory

            // open dir in filename buffer, parsed previously
            //printf("Running list on directory:%s\n", filename);
            DIR *dir = opendir(filename);
            if(dir){    // If the directory was valid
                //printf("Directory opened successfully.\n");
                while( (dent = readdir(dir) ) != NULL){     // Loop through all potential entities in this directory until there are none left
                    //printf("Got non-null directory entity: %s\n", dent->d_name);
                    if(!strncmp(".", dent->d_name, 1) || !strncmp("..", dent->d_name, 2)){ // Skip it if it "." or ".."
                        //printf("Continuing...\n");
                        continue;
                    }

                    memset(&file_ls, 0, sizeof(block_file));        // Clear the block file, name size, and name send buffers
                    memset(entname, 0, 256);
                    namesz = 0;

                    struct stat path;                               // Stat struct to get info on the dirent server is processing

                    char *fullpath = calloc(512, 1);                // Construct the full path to the entity from the server root directory
                    strncpy(fullpath, filename,256);                // Copy directory path
                    strncpy(fullpath + strlen(filename), dent->d_name, 256); // Append entity path

                    if(stat(fullpath, &path) != -1){                // Check if we can get a valid stat from it
                        if(S_ISREG(path.st_mode)){                  // Check if its a regular file
                            //printf("Got regular file for %s and %s.\n", fullpath, dent->d_name);
                            FILE *file = fopen(fullpath, "rb");     // Open the file
                            if(file) {                              // If valid
                                //printf("Opened file.\n");
                                fseek(file, 0, SEEK_SET);           // Seek the start and read the file_block there into the appropriate send buffer
                                int fbread = fread(&file_ls, sizeof(block_file), 1, file);
                                //printf("Read %d blocks from file.\n", fbread);
                                namesz = strlen(dent->d_name) + 1; // Save the name size of the dent plus room for a null terminator
                                fclose(file);
                            }
                        }else if(S_ISDIR(path.st_mode)){          // Check if its a regular directory
                            //printf("Got directory entity for %s and %s.\n", fullpath, dent->d_name);
                            memcpy(&file_ls, &dir_block, sizeof(block_file)); // Copy the directory block of 1s into the block file to send
                            namesz = strlen(dent->d_name) + 1;                // Save the name length with room for a null terminator
                        }

                        //printf("Sending reply_buffer.\n");
                        //printf("With blocks: (%d,%d)\n",file_ls.blocks_stored[0], file_ls.blocks_stored[1]);
                        //printf("Name sz: %d\n", namesz);
                        strncpy(entname, dent->d_name, 256);                 // Copy the entity name to the send buffer
                        //printf("And name: %s\n", entname);
                        send(*cl_fd, &file_ls, sizeof(block_file), 0);      // Send the file_block header
                        send(*cl_fd, &namesz, sizeof(int), 0);              // Send the file/dir name size (with terminator)
                        send(*cl_fd, entname, namesz, 0);                   // Send the filename with terminator
                    }

                    if(fullpath != NULL){   // If a fullpath was malloced, free it
                        free(fullpath);
                    }
                }   // Repeat loop through directory
            } else {    // Directory was invalid, send a file_block of 00s to signify this
                //printf("Directory failed to open.\n");
                block_file blank_block;
                memset(&blank_block, 0, sizeof(block_file));
                send(*cl_fd, &blank_block, sizeof(block_file), 0);
                //printf("Sent error (00s) response.\n");
            }
            //printf("Ending list run.\n");

            break;
        /*====================================================================================*/
        /*====================================MKDIR COMMAND===================================*/
        /*====================================================================================*/
        case 4:
            ;
            //printf("Running MKDIR command with args:%s\n", cl_data);
            dfs_cmd response;                           // dfs_cmd buffer to send result
            memset(&response,0, sizeof(dfs_cmd));
            int status = mkdir(filename, 0777);         // Make the request directory. filename is already parsed in beginning of this function
            if(status == -1){                           // On error, save the error code in response.cmd
                response.cmd = errno;
            }else{                                      // Otherwise save 0 for success
                response.cmd = status;
            }
            if(status){
                //printf("Directory not created\n");
            }
            send(*cl_fd, &response, sizeof(dfs_cmd), 0); // Send the response
            break;

        default:
            //printf("Got unrecognized command.\n");
            return 1;
    }

    return 0;
}

/*
 * Takes in received client command information and server config
 * Will verify if the user and MD5 password hash match to allowed database
 * Returns 0 if  user is not valid, 1 if user is valid.
 */
int verify_user(dfs_cmd *cmd, svr_config *config){
    for(int i = 0; i < config->user_count; i++){
        if(!strncmp(config->users[i], cmd->user, 16)){
            return compare_MD5s(config->pwd_MD5s[i], cmd->pass_MD5);
        }
    }
    return 0;
}

/*
 * Reads server config and setups svr_config passed in. Will fill user/passwords.
 * return: 1 on failure, 0 on success; config structure is filled with user/pass combos
 */
int svr_read_config(char *filename, svr_config *config){
    FILE *cfg_ptr = fopen(filename, "r");       // Open config file and ensure it exists
    if(cfg_ptr == NULL){
        //printf("Config file not found.\n");
        return 1;
    }

    char user_line[SZ_LINE];                           // Create buffers to hold a user and pw line read from cfg
    char pw_line[SZ_LINE];

    int ret;                                           // Hold the return value of parse_username_pw to exit loop
    int cnt = 0;                                       // How many users already inserted

    do{
        memset(user_line, 0, SZ_LINE);             // Clear the buffers
        memset(pw_line, 0, SZ_LINE);
        fgets(user_line, SZ_LINE, cfg_ptr);             // Get both lines. Next call will check for NULL returns
        fgets(pw_line, SZ_LINE, cfg_ptr);

        ret = parse_username_pw(user_line, pw_line);    // Parse the user/password lines from the config
        if(ret == 0){                                   // On success
            strncpy(config->users[cnt], user_line, 16); // Copy the user to next empty element
            strncpy(config->pwds[cnt], pw_line, 16);    // Copy the pass to the next empty element
            get_str_MD5(config->pwds[cnt], config->pwd_MD5s[cnt]); // Calculate and store PW hash
            cnt++;                                             // Increase the overall count
        }
    }while(ret != 1 || cnt >= 64);                      // Exit if parse_username_pw detects the end or too many are supplied

    fclose(cfg_ptr);

    if(cnt < 1){                                        // Ensure there is at least 1 valid user
        //printf("No usernames or passwords supplied.\n");
        return 1;
    }
    config->user_count = cnt;                           // Save the valid user count
    return 0;
}

/*
 * From tcpechoserver.c example provided by class
 * open_listenfd - open and return a listening socket on port
 * Returns -1 in case of failure
 */
int open_listenfd(int port) {
    int listenfd, optval = 1;
    struct sockaddr_in serveraddr;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &optval, sizeof(int)) < 0)
        return -1;

    /* listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short) port);
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 1024) < 0)
        return -1;
    return listenfd;
} /* end open_listenfd */
