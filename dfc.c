#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include <signal.h>
#include "dfsys.h"

#include <errno.h>    // For debug

typedef struct client_config {  // Structure holding DFS server information and user/pass
    struct sockaddr_in svrs[4]; // DFS Server information 1-4
    int svr_sockets[4];         // Socket descriptors for each server
    int socket_states[4];       // Connection state of each socket in same index. 1 = connected, 0 = disconnected
    char svr_names[4][16];      // DFS server str names
    char user[16];              // Plaintext user/pass
    char pass[16];
    unsigned char pass_MD5[MD5_DIGEST_LENGTH]; // Password in MD5 form.
    unsigned char key;          // XOR byte encryption key
} client_config;

typedef struct file_info {  // Data structure to hold file info received from LIST command
    char name[256];         // Filename
    char parts;             // Parts flag, b'0000 1111 = all parts; b'0001 = part 0
} file_info;

int cl_read_config(char *filename, client_config *config);
int cl_parse_cmd(char *cmd, dfs_cmd *out);
int cl_run_cmd(dfs_cmd *cmd, char *data, client_config *config);

int main(int argc, char **argv)
{
    /*====================================================================================*/
    /*===================================CONFIG PARSING===================================*/
    /*====================================================================================*/
    if(argc != 2){                          // Check argument count
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(0);
    }

    client_config cfg;                      // Create config structure and parse the passed config file
    if(cl_read_config(argv[1], &cfg)){
        fprintf(stderr, "Failed to parse config. See readme.md for structure.\n");
        exit(0);
    }
    signal(SIGPIPE, SIG_IGN);                   // Handle SIGPIPE locally in case server closes connection early
    unsigned char pwMD5[MD5_DIGEST_LENGTH];     // Buffer to hold the MD5 hash of the user password
    get_str_MD5(cfg.pass, pwMD5);               // Get the MD5 hash of the password and store it in the pwMD5 buffer
    cfg.key = MD5_to_key(pwMD5);                // Get the XOR key associated with their password hash

    printf("Parsed config successfully...\n"); // Pretty print config
    printf("----------------------------------------\n");
    printf("Got User:%s\n", cfg.user);
    printf("with pass:%s\n", cfg.pass);
    printf(" - MD5: ");
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
        printf("%02x", cfg.pass_MD5[i]);
    }
    printf("\n");
    printf("Calculated XOR Key: %02x\n", cfg.key);
    printf("-Retrieved servers (Host byte order)@--\n");
    printf("----------------------------------------\n");
    for(int i =0;  i< 4; i++){
        printf("Name: %s, IP: %d, port: %d\n", cfg.svr_names[i], htonl(cfg.svrs[i].sin_addr.s_addr), htons(cfg.svrs[i].sin_port));
    }
    printf("----------------------------------------\n");

    /*====================================================================================*/
    /*=====================================INPUT LOOP=====================================*/
    /*====================================================================================*/
    char user_input[SZ_CMD_BUFF];       // Create STDIN buffer for user input
    dfs_cmd user_cmd;                   // Define dfs_cmd structure to be filled

    // Print instructions to user
    printf("Input commands... get <file> <opt. DIR>, put <FILE> <opt. DIR>, list <opt. DIR>, or mkdir <dir>\n");
    printf("Directories are optional for GET/PUT/LIST. Will default to root user directory.\n");
    printf("Directories must end with a '/' character for put, get, and list.\n");
    printf("Please put command name (get/put/etc) in all lowercase. Arguments are case-sensitive.\n");
    printf("Exit with command 'exit'\n");
    // Input loop until 'exit' command is given or ctrl+c
    while(1){
        printf("-> ");

        memset(&user_input, 0, SZ_CMD_BUFF);      // Clear input buffer and cmd structure
        memset(&user_cmd, 0, sizeof(dfs_cmd));
        strncpy(user_cmd.user, cfg.user, 16);   // Copy the username & pass md5 into cmd struct for verification
        memcpy(user_cmd.pass_MD5, cfg.pass_MD5, MD5_DIGEST_LENGTH);

        fgets(user_input, SZ_CMD_BUFF, stdin); // Get user input

        cl_parse_cmd(user_input, &user_cmd);          // Pass user inputted data and cmd struct to be filled into cl_parse

        if(user_cmd.cmd < 1){                         // If the command is invalid after parsing
            continue;                                 // Continue and re-prompt user
        }

        cl_run_cmd(&user_cmd, user_input, &cfg);      // On valid command, call run_cmd with cmd struct, data args, and client config
    }
    return 0;
}

/*
 * Takes a dfs_cmd structure, its associated data (can be all null), and the client config
 * Runs command specified in passed structure by connecting to servers from config and attempting to
 * send and complete the command.
 */
int cl_run_cmd(dfs_cmd *cl_cmd, char *data, client_config *config){
    /*====================================================================================*/
    /*=================================Connect to Servers=================================*/
    /*====================================================================================*/
    FILE *curr_file;                                                // File to send/recv if PUT or GET
    char *curr_file_name;                                           // (full local path)Name of above FILE*

    if(cl_cmd->cmd == 2 || cl_cmd->cmd == 1){                         // Process optional directory argument if put/get command
        data[strcspn(data, " ")] = '\0';                      // Make filename and dir separate strings in data[] buffer
        if(cl_cmd->cmd == 2){
            curr_file = fopen(data, "rb");                      // Try to open file to put
        }else{
            curr_file = fopen(data, "wb+");                      // Try to open file to get
        }

        if(curr_file == NULL && cl_cmd->cmd == 2){                    // If it doesn't exist print error and return, don't send command
            printf("Can't send: %s; File does not exist on client.\n", data);
            return 1;
        }else if(curr_file == NULL && cl_cmd->cmd == 1){
            printf("Can't open local file %s to receive from servers.\n", data);
            return 1;
        }

        curr_file_name = calloc(256, 1);                                // Alloc buffer to hold local path+name and save it
        strncpy(curr_file_name, data, 255);

        if(strlen(data) + 1 != cl_cmd->data_len){                    // If a directory argument was supplied
            char *full_path;                                         // Copy fullpath for server i.e. "<file> <dir>" -> "<dir>/<file>" and save to data
            full_path = calloc(512 , 1);
            strncpy(full_path, data+strlen(data)+1, 255);
            strncpy(full_path + strlen(full_path), data, 255);

            strncpy(data, full_path, SZ_CMD_BUFF);
            free(full_path);
            cl_cmd->data_len = strlen(data) + 1;
        }
    }

    char cmd_packet[SZ_CMD_BUFF + sizeof(dfs_cmd)];                 // Create buffer to hold command packet that will be sent
                                                                    // Size of potential input + the dfs_cmd header
    memset(cmd_packet, 0, SZ_CMD_BUFF + sizeof(dfs_cmd));    // Clear send buffer
    memcpy(cmd_packet, cl_cmd, sizeof(dfs_cmd));                       // Copy the parsed command struct into the start of the buffer
    memcpy(cmd_packet + sizeof(dfs_cmd), data, cl_cmd->data_len); // Copy the data (if any file/directory path) after this dfs_cmd header

    struct timeval socket_to;                                       // Create 1 second time struct for connect() timeout
    socket_to.tv_sec = 1;
    socket_to.tv_usec = 0;

    for(int i = 0; i < 4; i++){                                     // For each of the 4 potential servers
        config->svr_sockets[i] = socket(AF_INET, SOCK_STREAM, 0);   // Open a TCP ipv4 socket for a server connection

        if(config->svr_sockets[i] > 0){                             // If the socket is valid after opening
            // Set a 1 second timeout for connect()
            if(setsockopt(config->svr_sockets[i], SOL_SOCKET, SO_SNDTIMEO, &socket_to, sizeof(socket_to)) < 0){
                // On setsockopt error, set the socket as invalid and close it. Make sure state is invalid
                printf("Failed to set socket connect timeout for server socket: %s\n", config->svr_names[i]);
                config->socket_states[i] = 0;
                close(config->svr_sockets[i]);
                continue;
            }
            // Attempt to connect to the appropriate server on the new TCP socket
            if(connect(config->svr_sockets[i], (struct sockaddr *)&config->svrs[i], sizeof(struct sockaddr_in)) < 0){
                // On failure or timeout, close the socket and continue
                printf("Failed to connect to server: %s\n", config->svr_names[i]);
                config->socket_states[i] = 0; // Set socket state as invalid
                close(config->svr_sockets[i]);
                continue;
            }else{                            // On connect() success
                config->socket_states[i] = 1; // Set the socket state to valid
                continue;
            }
        }
        printf("Failed to open TCP socket for server: %s\n", config->svr_names[i]); // Socket wasn't valid on socket()
        config->socket_states[i] = 0;                                                      // Set the state as invalid
    }

    socket_to.tv_sec = 5;                   // Change the timeout value to 5 second for the rest of the command

    for(int i = 0; i < 4; i++){             // For each potential server
        if(config->socket_states[i]){       // If the socket is open and valid
                                            // Set send() and recv() timeouts of 5 seconds each
            int ret = setsockopt(config->svr_sockets[i], SOL_SOCKET, SO_SNDTIMEO, &socket_to, sizeof(socket_to));
            ret = ret | setsockopt(config->svr_sockets[i], SOL_SOCKET, SO_RCVTIMEO, &socket_to, sizeof(socket_to));
            if(ret != 0){                   // Check return of both calls with ret and print on failure
                printf("Failed to set send or recv timeout for server socket: %s\n", config->svr_names[i]);
            }
        }
    }

    /*==============================Send command to servers===============================*/

    for(int i = 0; i < 4; i++){             // For each potential server
        if(config->socket_states[i]){       // If the socket is open and valid
            int sent = send(config->svr_sockets[i], cmd_packet, (cl_cmd->data_len + sizeof(dfs_cmd)), 0); // Send cmd_packet to server
            printf("Sent %d/%d command bytes to server: %s\n", sent, (int)(cl_cmd->data_len + sizeof(dfs_cmd)), config->svr_names[i]);
        }
    }

    /*====================================================================================*/
    /*==================================Carry out command=================================*/
    /*====================================================================================*/

    switch(cl_cmd->cmd){                    // Switch statement on command to carry out command with servers
        /*====================================================================================*/
        /*=====================================GET COMMAND====================================*/
        /*====================================================================================*/
        case 1:
            printf("Getting file...\n");
            ;
            int len_user = strlen(config->user);

            char *cacheNames[4];    // Dynamic names of cache files for all 4 parts
            FILE *cache[4];         // Pointers to these cache files
            for(int i = 0; i < 4; i++){
                cacheNames[i] = calloc(64, 1);          // Alloc its name and make it "username-dfc_chace_file_#
                strncpy(cacheNames[i], config->user, 16);
                sprintf(cacheNames[i] + len_user, "-dfc_cache_file_%d", i);
                cache[i] = fopen(cacheNames[i], "wb+");      // Open the dynamically named cache files
            }

            block_file fileParts[4];                            // Block_file structs to hold file information from received from servers
            unsigned char fileMD5[MD5_DIGEST_LENGTH];           // Expected file MD5 hash received from servers
            int blocks_completed[4] = {0, 0, 0, 0};             // State of blocks in the cache. 0 = empty, 1 = present
            int succ = 0;                                       // Was GET successful

            if(cache[0] && cache[1] && cache[2] && cache[3]){   // If the cache files w ere opened properly
                char parts = 0;                                 // Byte to hold track of parts received. 0xF = all received
                for(int serverNbr = 0; serverNbr < 4; serverNbr++){
                    if(config->socket_states[serverNbr]){       // Loop through connected servers and receive a block_file
                        int bytesGot = recv(config->svr_sockets[serverNbr], &fileParts[serverNbr], sizeof(block_file), 0);
                        if(bytesGot == sizeof(block_file)){     // If we got a valid amount of bytes
                                                                // If both blocks_stored are 0, its not valid -> assume server does not have the file
                            if(fileParts[serverNbr].blocks_stored[0] == 0 && fileParts[serverNbr].blocks_stored[1] == 0){
                                printf("File did not exist on server: %s\n", config->svr_names[serverNbr]);
                            }else{                              // Otherwise OR the parts on this server into our overall parts tracker
                                parts = parts | block_index_to_flag(fileParts[serverNbr].blocks_stored[0]);
                                parts = parts | block_index_to_flag(fileParts[serverNbr].blocks_stored[1]);
                            }
                        }
                    }
                }
                if(parts == 0xF){                               // Available servers can serve the full file
                    printf("All parts available, receiving full file now.\n");
                    char fileBuffer[SZ_FILE_BUFF];              // Buffer to handle file transfering from servers
                    for(int i = 0; i < 4; i++){
                        if(config->socket_states[i]){
                            if(fileParts[i].blocks_stored[0] != 0 || fileParts[i].blocks_stored[1] != 0){   // Loop through valid servers that sent a valid block_file
                                //printf("Got valid file block and open connection to server: %d\n", i);
                                memcpy(fileMD5, &fileParts[i].full_MD5, MD5_DIGEST_LENGTH);                 // Copy the MD5 digest from the block_file to our fileMD5 buffer. All valid blocks will have the same hash value
                                int bytesToRead = fileParts[i].block_lens[fileParts[i].blocks_stored[0]];   // Calculate the number of incoming file bytes from the information in the block_file received from this server for the first block
                                //printf("Must read %d bytes from part %d.\n", bytesToRead, fileParts[i].blocks_stored[0]);
                                while(bytesToRead > 0){                                                     // If the client is still expecting bytes for this first block, keep receiving
                                    //printf("%d bytes to read 1st block.\n", bytesToRead);
                                    memset(fileBuffer, 0, SZ_FILE_BUFF);                               // If bytesToRead >= SZ_FILE_BUFF bytes use the full buffer, otherwise use bytesToRead bytes of it
                                    int toRead = bytesToRead >= SZ_FILE_BUFF ? SZ_FILE_BUFF : bytesToRead;
                                    //printf("Toread:%d\n", toRead);
                                    int bytesRead = recv(config->svr_sockets[i], fileBuffer, toRead, 0);    // Receive the bytes toRead this iteration
                                    if(bytesRead <= 0){                                                     // If the server isn't sending, exit the loop
                                        break;
                                    }
                                    //printf("Recved: %d/%d\n", toRead, bytesRead);
                                    xor_bytes(fileBuffer, bytesRead, config->key);                          // Decrypt the bytes based on the users KEY
                                    if(blocks_completed[fileParts[i].blocks_stored[0]] != 1){               // If we haven't already cached the block we are receiving
                                        //printf("Writing cache file: %d\n", fileParts[i].blocks_stored[0]);
                                        int fwrote = fwrite(fileBuffer, 1, bytesRead, cache[fileParts[i].blocks_stored[0]]); // Cache it into the correct cache file
                                        //printf("wrote %d/%d bytes.\n", fwrote, bytesRead);
                                    }
                                    bytesToRead -= bytesRead;                                               // Decrement our receive counter by the number of bytes read
                                }
                                blocks_completed[fileParts[i].blocks_stored[0]] = 1;                        // Mark the block as completed as to not recache the part

                                bytesToRead = fileParts[i].block_lens[fileParts[i].blocks_stored[1]];       // Calculate the bytes expected for the 2nd part being received from this server
                                while(bytesToRead > 0/*< fileParts->block_lens[fileParts[i].blocks_stored[1]]*/){ // Receive/cache these bytes as above
                                    //printf("%d bytes to read for 2nd block.\n", bytesToRead);
                                    memset(fileBuffer, 0, SZ_FILE_BUFF);
                                    int toRead = bytesToRead >= SZ_FILE_BUFF ? SZ_FILE_BUFF : bytesToRead;
                                    //printf("Must read %d bytes from part %d.\n", bytesToRead, fileParts[i].blocks_stored[1]);
                                    int bytesRead = recv(config->svr_sockets[i], fileBuffer, toRead, 0);
                                    xor_bytes(fileBuffer, bytesRead, config->key);
                                    if(blocks_completed[fileParts[i].blocks_stored[1]] != 1){
                                        //printf("Writing cache file: %d\n", fileParts[i].blocks_stored[1]);
                                        int fwrote = fwrite(fileBuffer, 1, bytesRead, cache[fileParts[i].blocks_stored[1]]);
                                        //printf("wrote %d/%d bytes.\n", fwrote, bytesRead);
                                    }
                                    bytesToRead -= bytesRead;
                                }
                                blocks_completed[fileParts[i].blocks_stored[1]] = 1;
                                //printf("Done handling server: %d\n", i);
                            }
                        }
                    }

                    // assemble file from cache files
                    // Copy cache0 to final, then cache1 to final, etc, etc
                    for(int i = 0; i < 4; i ++){
                        if(blocks_completed[i] == 1){                                               // For all completed cache files IN ORDER 0,1,2,3
                            //printf("Assembling completed block %d\n", i);
                            fseek(cache[i], 0, SEEK_SET);                                    // Reseek the start of the cache
                            while (1){                                                              // Write all bytes in the cache file to the final file
                                memset(fileBuffer, 0, SZ_FILE_BUFF);
                                int sz = fread(fileBuffer, 1, SZ_FILE_BUFF, cache[i]);
                                //printf("Read %d bytes.\n", sz);
                                if(sz <= 0){
                                    break;
                                }
                                int wrote = fwrite(fileBuffer, 1, sz, curr_file);
                                //printf("Wrote %d/%d bytes to final file.\n", wrote, sz);
                            }
                        }
                    }

                    unsigned char MD5_curr_file[MD5_DIGEST_LENGTH];         // Calculate the MD5 hash of this newly assembled file
                    memset(MD5_curr_file, 0, MD5_DIGEST_LENGTH);
                    get_file_MD5(curr_file, MD5_curr_file);
                    printf(" - Expected MD5: ");                    // Print the MD5 hash the servers supplied
                    for(int j = 0; j < MD5_DIGEST_LENGTH; j++){
                        printf("%02x", fileMD5[j]);
                    }
                    printf("\n");
                    printf(" - Retrieved MD5: ");                   // Print the assembled file's MD5
                    for(int j = 0; j < MD5_DIGEST_LENGTH; j++){
                        printf("%02x", MD5_curr_file[j]);
                    }
                    printf("\n");
                    if(compare_MD5s(MD5_curr_file, fileMD5) == 1){         // Compare the two, print message and set flags based on equality
                        printf("Successful. Files are identical.\n");
                        succ = 1;
                    }else{
                        printf("MD5 mismatch, failed to retrieve.\n");
                        succ = 0;
                    }
                } else {                                                    // Didn't have all parts, print message
                    printf("File is incomplete, can not get it.\n");
                }

                for(int i = 0; i < 4; i++){                                 // Close all 4 cache files, remove them from disk, and free their dynamic name buffers
                    fclose(cache[i]);
                    remove(cacheNames[i]);
                    free(cacheNames[i]);
                }
            }

            fclose(curr_file);                                              // Close the final file the client was GETing
            if(!succ){                                                      // If it was unsuccessful, remove the empty file meant to receive
                remove(curr_file_name);
            }
            free(curr_file_name);                                           // Free the name buffer for the final file
            break;
        /*====================================================================================*/
        /*=====================================PUT COMMAND====================================*/
        /*====================================================================================*/
        case 2:
            printf("Putting file to location:%s\n", data);

            unsigned char ts_md5[16];                       // Get the full file MD5
            get_file_MD5(curr_file, ts_md5);
            int scheme = MD5_to_pairs(ts_md5);              // Calculate file scheme (from writeup table) with %4 on hash
            printf("Computed file MD5: ");
            for(int i = 0; i < MD5_DIGEST_LENGTH; i++){ printf("%02x", ts_md5[i]); }
            printf("\n");
            printf("Splitting file based on x = %d\n", scheme);

            fseek(curr_file, 0, SEEK_END);          // Get the overall file size that will be sent
            long ts_size = ftell(curr_file);
            fseek(curr_file, 0, SEEK_SET);

            int block_sizes[4] = {0, 0, 0, 0};             // Break it up into 4 even sizes, any overflow will be added to first block size
            for(int i = 0; i < 4; i++){
                block_sizes[i] = i == 0 ? ts_size/4 + ts_size%4 : ts_size/4;
            }
            printf("Sending blocks:\n");
            for(int i = 0; i < 4; i++){
                printf(" -- block(%d): %d bytes\n", i, block_sizes[i]);
            }

            // i = 0 = (0,1)
            // i = 1 = (1,2)
            // i = 2 = (2,3)
            // i = 3 = (3,0)
            // ( i + x ) mod 4 to get server to send to. Will ensure scheme is kept
            for(int i = 0; i < 4; i++){                         // Loop through 4 possible pairs to be sent
                int target_svr = (i + scheme) % 4;              // Calculate the correct server to target based on file MD5
                if(config->socket_states[target_svr]){
                    block_file to_send_info;                    // If the server is connected, create a block_file header for the calculated block sizes and iteration
                    memset(&to_send_info, 0, sizeof(block_file));
                    memcpy(&to_send_info.block_lens, block_sizes, sizeof(int[4]));
                    memcpy(&to_send_info.full_MD5, ts_md5, MD5_DIGEST_LENGTH);
                    short block1 = i;                           // Calculate the 2 blocks to send after the header based on iteration
                    short block2 = (i + 1)%4;

                    to_send_info.blocks_stored[0] = block1;     // Encode this into the header we will send
                    to_send_info.blocks_stored[1] = block2;

                    int b1_start, b2_start;                     // offsets from SEEK_SET in FILE to send of the blocks to be sent

                    get_block_offsets(block1, to_send_info.block_lens, &b1_start); // Calculate the offsets for the 2 blocks to be sent
                    get_block_offsets(block2, to_send_info.block_lens, &b2_start);


                    printf("Sending blocks (%d,%d) to server: %s\n", block1, block2, config->svr_names[target_svr]);

                    //char send_buffer[sizeof(block_file)];                          // Create a block_file sized buffer to send this new block file
                    //memset(send_buffer, 0, sizeof(block_file));
                    //memcpy(send_buffer, &to_send_info, sizeof(block_file));        // Copy the created block_file to the buffer

                    //send(config->svr_sockets[target_svr], send_buffer, sizeof(block_file), 0); //

                    send(config->svr_sockets[target_svr], &to_send_info, sizeof(block_file), 0); // Send created file_block to server
                    // Send the first block directly after, encrypted with user KEY. Will send block starting at offset
                    if(send_file_tcp(curr_file, b1_start, to_send_info.block_lens[block1], config->key, config->svr_sockets[target_svr]) < 0){
                        printf("Send failed on block %d on target_svr: %d", 1, target_svr);
                    }
                    // Send the second block in the same way with its offset and length
                    if(send_file_tcp(curr_file, b2_start, to_send_info.block_lens[block2], config->key, config->svr_sockets[target_svr]) < 0){
                        printf("Send failed on block %d on target_svr: %d", 2, target_svr);
                    }

                }
            }
            // Free up the file ptr and name the client PUT
            fclose(curr_file);
            free(curr_file_name);

            break;
        /*====================================================================================*/
        /*====================================LIST COMMAND====================================*/
        /*====================================================================================*/
        case 3:
            ;
            char *directories = malloc(256*256);                    // 1D array of 256*256 characters. Will treat as a 2d (256x256 char dir names)
                                                                         // Will hold all directories returned by LIST
            int directoryCount = 0;                                      // Current number of received directories
            file_info *files = malloc(sizeof(file_info)*256);       // Array of file_info structures. Has char filename[256] and char parts
            int fileCount = 0;                                           // Current number of received files

            block_file fileBlock;                                        // Buffer to receive block_file headers from servers
            for(int serverNumber = 0; serverNumber < 4; serverNumber++){ // Loop through valid servers of the 4
                while(1 && config->socket_states[serverNumber] == 1){
                    memset(&fileBlock, 0, sizeof(block_file));      // Clear and recv a block_file into the fileBlock buffer
                    int bytesGot = recv(config->svr_sockets[serverNumber], &fileBlock, sizeof(block_file), 0);

                    if(bytesGot <= 0){                                  // Break from this server if we aren't receiving bytes
                        //printf("Didn't receive response from server %s\n", config->svr_names[serverNumber]);
                        break;
                    }else{                                              // If valid bytes are received
                        //printf("Recv: len %d %d %d %d\n", fileBlock.block_lens[0], fileBlock.block_lens[1], fileBlock.block_lens[2], fileBlock.block_lens[3]);
                        //printf("Storing (%d,%d)\n", fileBlock.blocks_stored[0], fileBlock.blocks_stored[1]);
                        if(fileBlock.blocks_stored[0] == 0 && fileBlock.blocks_stored[1] == 0){ // Check if the blocks_stored are 0, this means its empty or non-existent
                            printf("Bad directory name or empty directory: server %s\n", config->svr_names[serverNumber]);
                        }else{                                          // If valid file_block
                            char fullFileName[256];                     // Buffer to hold the filename sent next
                            memset(fullFileName, 0, 256);
                            int dirNameSize;                            // Integer to hold the size of the name to recv()
                            bytesGot = recv(config->svr_sockets[serverNumber], &dirNameSize, sizeof(int), 0); // Recv the length of the name
                            if(bytesGot <= 0){  // Make sure we received a size, and if so receive that size into the filename char buffer
                                printf("Recv failed on filename/dir length in LIST\n");
                                break;
                            }else{
                                bytesGot = recv(config->svr_sockets[serverNumber], fullFileName, dirNameSize, 0);
                            }

                            // Check if the blocks stored are all full 1s, this means its a directory
                            if(fileBlock.blocks_stored[0] == 257 && fileBlock.blocks_stored[1] == 257){
                                // Its a directory
                                int found = 0;                           // Flag if the directory has been found in the directories data structure
                                for(int i = 0; i < directoryCount; i++){ // Loop through all current received directories
                                    if(strncmp(directories + (i*256), fullFileName, 256) == 0){ // Set the flag if any of the names match
                                        found = 1;
                                    }
                                }
                                if(!found){                             // If it's not in the directories data structure
                                    if(directoryCount < 256){           // Add it if we have room
                                        strncpy(directories + (directoryCount*256), fullFileName, 256);
                                        directoryCount++;
                                    }else{
                                        printf("LISTed directory has >256 directories, truncating...\n");
                                    }
                                }
                            }else{ //Not a directory, assume file
                                int index = -1;                     // Index to hold if we've found the file in our file_info array
                                for(int i = 0; i < fileCount; i++){ // Check if the filename is in the struct array. If so save the index
                                    if(strncmp(files[i].name, fullFileName, 256) == 0){
                                        index = i;
                                        break;
                                    }
                                }
                                if(index == -1){                   // If the file wasn't found, append it to the data structure and save that index
                                    strncpy(files[fileCount].name, fullFileName, 256);
                                    files[fileCount].parts = 0;    // Append new filename with no parts received
                                    index = fileCount;
                                    fileCount++;

                                }
                                // 0 = b'0001
                                // 1 = b'0010
                                // 2 = b'0100
                                // 3 = b'1000
                                // 0xf = b'1111 = file is complete
                                int b1 = fileBlock.blocks_stored[0] + 1; // Convert integer block index to correct bit flag, must add 1 first
                                int b2 = fileBlock.blocks_stored[1] + 1;

                                b1 = b1 == 4 ? 8 : b1;                   // If block1 index is 4, set it to 8 to get correct flag (b'1000)
                                b1 = b1 == 3 ? 4 : b1;                   // If block1 index is 3, set it to 4 to get correct flag (b'0100)
                                b2 = b2 == 4 ? 8 : b2;                   // Repeat. Flags for parts (0,1) will be correct already
                                b2 = b2 == 3 ? 4 : b2;

                                files[index].parts = files[index].parts | b1 | b2; // Or the bits of the parts the server has to all parts stored in the data struture


                                //files[index].parts = files[index].parts | block_index_to_flag(fileBlock.blocks_stored[0]) | block_index_to_flag(fileBlock.blocks_stored[0]);

                            }
                        }
                    }
                }
            }
            // Pretty print the received directories and files
            printf("------------------List response------------------\n");
            if(directoryCount > 0){
                printf("Directories:\n");
                for(int i=0; i < directoryCount; i++){
                    printf("--%s/\n", directories + (i*256));
                }
            }
            if(fileCount > 0){
                printf("Files:\n");
                for(int i = 0; i < fileCount; i++){
                    if((files[i].parts & 0xF) == 0xF){
                        printf("--%s\n", files[i].name);
                    }else{
                        printf("--%s[incomplete]\n ", files[i].name);
                    }

                }
            }
            if(fileCount == 0 && directoryCount == 0){
                printf("EMPTY\n");
            }
            printf("-------------------------------------------------\n");
            // Free the mallocs made to hold received files/directories
            free(directories);
            free(files);
            break;
        /*====================================================================================*/
        /*====================================MKDIR COMMAND===================================*/
        /*====================================================================================*/
        case 4:
            ;
            dfs_cmd response;                   // Buffer to hold the response from each server
            for(int i=0; i < 4; i++){
                if(config->socket_states[i]){   // Loop through all 4 servers, and if valid:
                    if(recv(config->svr_sockets[i], &response, sizeof(dfs_cmd), 0) < sizeof(dfs_cmd)){  // Receive the response
                        printf("Server %s returned incomplete response to MKDIR.\n", config->svr_names[i]);
                    }else{                                                                              // Print the mkdir return from the server
                        if(response.cmd == 0){          // Success
                            printf("Directory successfully created on server: %s\n", config->svr_names[i]);
                        }else if(response.cmd == 17){   // FILEEXIST error
                            printf("Directory already exists on server: %s\n", config->svr_names[i]);
                        }else{                          // Other errors
                            printf("Directory creation failed on server: %s with code %d\n", config->svr_names[i], response.cmd);
                        }
                    }

                }
            }

            break;
        default:
            printf("I don't know how you did this: invalid command in cl_run_cmd().\n");
    }

    /*====================================================================================*/
    /*===================================SOCKET CLEANUP===================================*/
    /*====================================================================================*/
    for(int i = 0; i < 4; i++){             // For each potential server
        if(config->socket_states[i]){       // Close the socket if it was open and valid
            close(config->svr_sockets[i]);
        }
    }

    return 0;
}

/*
 * Takes a user inputted command string and a command header to fill on success
 * Returns 1 on failure, 0 on success; Cmd struct filled and cmd sanitized to hold just the argument
 */
int cl_parse_cmd(char *cmd, dfs_cmd *out){
    cmd[strcspn(cmd, "\n")] = '\0'; // Sanitize out '\n' characters;

    int len_input = strlen(cmd);            // Overall length
    int bytes_to_remove = 0;                // Bytes to be shifted out of the input string (i.e. 'get ')


    if(!strncmp(cmd, "get", 3)){            // Check if the the command is recognized
        out->cmd = 1;                       // Set the cmd struct with the appropriate id
        bytes_to_remove = 4;                // Set bytes to be removed based on command length
    }
    else if(!strncmp(cmd, "put", 3)){       // Same
        out->cmd = 2;
        bytes_to_remove = 4;
    }
    else if(!strncmp(cmd, "list", 4)){      // Similar
        out->cmd = 3;
        if(len_input < 6){                  // If the "list" command was supplied without args
            out->data_len = 0;              // No data, but still valid
        }else{
            bytes_to_remove = 5;            // Otherwise, set 'list ' to be copied out to retrieve arg
        }
    }
    else if(!strncmp(cmd, "mkdir", 5)){
        out->cmd = 4;
        bytes_to_remove = 6;
    }
    else if(!strncmp(cmd, "exit", 4)){      // If exit was supplied, exit the whole client
        printf("Exiting...\n");
        exit(0);
    }else{                                  // If unrecognized, set error cmd and return
        out->cmd = -1;
        printf("Command unrecognized...\n");
        return 1;
    }

    if(bytes_to_remove > 0){                // If there is data to be sanitized ('get file123' -> 'file123')
        if(len_input > bytes_to_remove){    // If the input has an argument at all
            memcpy(cmd, cmd + bytes_to_remove, (len_input - bytes_to_remove + 1)); // Copy out cmd beginning. memcpy is safe these will never overlap
            out->data_len = len_input - bytes_to_remove + 1;    // Set the final length of the sanitized data
        }else{                              // Input had not argument, set error cmd and return
            out->cmd = -1;
            printf("No argument supplied for command.\n");
            return 1;
        }
    }else{                                  // If LIST was supplied with no arg, still valid just clear data buffer
        memset(cmd, 0, SZ_CMD_BUFF);
    }

    return 0;                               // Success
}

/*
 * Reads client config file and sets up client_config structure
 * return: 1 on failure, 0 on success; Config argument is filled on success
 */
int cl_read_config(char *filename, client_config* config)
{
    FILE *cfg_ptr = fopen(filename, "r");   // Open file and exit if it doesn't exist
    if(cfg_ptr == NULL){
        printf("Config file not found.\n");
        return 1;
    }

    char line[SZ_LINE];                            // Buffer to hold lines read from config

    memset(config, 0, sizeof(client_config)); // Zero the config struct to be filled
    char *save_ptr;                                // strtok_r pointers
    char *token = NULL;

    for(int i = 0; i < 4; i++){                    // Parse 4 server config lines
        memset(line, 0, SZ_LINE);             // Zero the line buffer and token ptr
        token = NULL;

        if(fgets(line, SZ_LINE, cfg_ptr) == NULL){ // Get the file line and ensure it succeeded
            printf("Config is missing server parameters.\n");
            fclose(cfg_ptr);
            return 1;
        }
        token = strtok_r(line, " ", &save_ptr); // See if there is a "Server" identifier first
        if(token == NULL){
            printf("Server config: %d is bad.\n", i);
            fclose(cfg_ptr);
            return 1;
        }
        if(strncmp(token, "Server", 6) != 0){
            printf("Server config: %d is bad.\n", i);
            fclose(cfg_ptr);
            return 1;
        }

        token = strtok_r(NULL, " ", &save_ptr); // Get pointer to the server name
        if(token == NULL){
            printf("Server config: %d is bad.\n", i);
            fclose(cfg_ptr);
            return 1;
        }

        strncpy(config->svr_names[i], token, 16); // Save the server name in the config

        token = strtok_r(NULL, " ", &save_ptr);          // Get the ip:port pointer and ensure it exists
        if(token == NULL){
            printf("Server config: %d is bad.\n", i);
            fclose(cfg_ptr);
            return 1;
        }

        char *ip = token;

        char *port = strstr(ip, ":");           // Find where the port begins if it exists
        if(port == NULL){
            printf("No port in server config line %d.\n", i);
            fclose(cfg_ptr);
            return 1;
        }

        *port = '\0';                                 // Replace the ':' with a terminator creating 2 strings (IP and Port)

        port = port + 1;                              // Adjust the port pointer to the correct position

        if(inet_pton(AF_INET, ip, &(config->svrs[i].sin_addr)) != 1){ // Convert IP string to a numeric IP
            printf("Bad IP on config line: %d\n", i);
            fclose(cfg_ptr);
            return 1;
        }
        config->svrs[i].sin_family = AF_INET;                          // Fill the correct sockaddr_in struct for the server
        config->svrs[i].sin_port = htons((unsigned short) atoi(port)); // Convert the port string to an integer and put it in network byte order
    }

    char line2[SZ_LINE];                    // Buffer to hold PW line (user is in line #1)
    memset(line, 0, SZ_LINE);          // Zero both buffers
    memset(line2, 0, SZ_LINE);

    fgets(line, SZ_LINE, cfg_ptr);          // Extract both lines, user should always come first
    fgets(line2, SZ_LINE, cfg_ptr);

    if(parse_username_pw(line, line2)){     // Parse both lines for correctness
        printf("Could not parse username or password in config.\n");
        fclose(cfg_ptr);
        return 1;
    }
    strncpy(config->user, line, 16); // Copy the user/pass output if it was correct
    strncpy(config->pass, line2, 16);
    get_str_MD5(config->pass, config->pass_MD5); // Calculate and store PW hash

    fclose(cfg_ptr);
    return 0;
}
