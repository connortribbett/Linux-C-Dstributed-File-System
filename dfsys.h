#ifndef DF_SYS_H
#define DF_SYS_H

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
#include <ctype.h>         // tolower()

#define SZ_FILE_BUFF 16384 // Size of buffer when sending command responses
#define SZ_CMD_BUFF  1024 // Size of a command sent to DFS servers
#define SZ_LINE      64   // Size of line read from config

typedef struct dfs_cmd { // Header structure to hold information on a client command & auth info
    short cmd;           // -1 or 0 = error, never sent. 1 = GET, 2 = PUT, 3 = LIST, 4 = MKDIR
    int data_len;        // Length of data sent with command (file/dir name). List could be 0 for root.
    char user[16];       // User and their MD5 password hash
    unsigned char pass_MD5[MD5_DIGEST_LENGTH];
} dfs_cmd;

typedef struct block_file {                    // Header structure for a split file. Every stored pair has this first
    int block_lens[4];                         // Length of all blocks in order
    short blocks_stored[2];                    // Indices of blocks stored in file
    unsigned char full_MD5[MD5_DIGEST_LENGTH]; // Full MD5 hash of the full file when reconstructed.
} block_file;

int get_str_MD5(char *str, unsigned char *rawMD5);
void get_file_MD5(FILE *file, unsigned char *rawMD5);
void MD5_to_str(unsigned char *rawMD5, char *output);
unsigned int MD5_to_pairs(unsigned char *rawMD5);
unsigned char MD5_to_key(unsigned char *rawMD5);
int compare_MD5s(unsigned char *rawMD5_1, unsigned char *rawMD5_2);
char block_index_to_flag(short index);
void get_block_offsets(int block, int *sz_blocks, int *start);
int send_file_tcp(FILE *file, long offset, long bytes_to_send, unsigned char key, int sock);
void xor_bytes(unsigned char *bytes, unsigned int len, unsigned char key);
void string_to_lower(char *str);
int parse_username_pw(char *user_line, char *pw_line);


/*====================================================================================*/
/*=====================================MD5 HELPERS====================================*/
/*====================================================================================*/

/*
 * Takes c string and a md5 byte buffer. String will be hashed into the buffer.
 * return: 1 on failure, 0 on success; md5 buffer argument is filled on success.
 */
int get_str_MD5(char *str, unsigned char *rawMD5){
    memset(rawMD5, 0, MD5_DIGEST_LENGTH);   // Clear out raw md5 buffer
    MD5_CTX context;                        // Create the MD5 context and initiliaze it
    MD5_Init(&context);
    MD5_Update(&context, str, strlen(str)); // Update the context with the passed string
    MD5_Final(rawMD5, &context);            // Finalize the hash into the passed raw buffer

    /*if(rawMD5[0] == 0){
        return 0;
    }*/
    return 1;
}

/*
 * Takes a filled raw md5 buffer and an empty c str buffer.
 * Raw md5 is outputted as a hex string into output.
 */
void MD5_to_str(unsigned char *rawMD5, char *output){
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++){ // Pass each MD5 byte through sprintf into the str buffer
        sprintf((output + i*2), "%02x", rawMD5[i]);
    }
    output[MD5_DIGEST_LENGTH * 2 + 1] = '\0'; // Null terminate the output
}

/*
 * Takes a valid file pointer in 'rb' mode and an empty MD5 byte buffer
 * Calculates the MD5 hash of the file contents and fills buffer *rawMD5
 */
void get_file_MD5(FILE *file, unsigned char *rawMD5){
    memset(rawMD5, 0, MD5_DIGEST_LENGTH);   // Clear out the raw MD5 output buffer
    MD5_CTX context;                        // Define and init empty MD5 context
    MD5_Init(&context);

    char file_buffer[1024];                 // Buffer to hold bytes read from file

    fseek(file, 0, SEEK_SET);        // Seek th beginning of the file
    int bread = 0;                          // Number of bytes read from file
    do{
        bread = 0;                                      // Reset bytes read
        memset(file_buffer, 0, 1024);         // Clear buffer
        bread = fread(file_buffer, 1, 1024, file); // Read up to 1024 bytes from the file
        MD5_Update(&context, file_buffer, bread); // Update the MD5 context with the number of bytes read
    }
    while(bread == 1024);                         // Repeat this unless <1024 bytes were read. In this case EOF was reached

    MD5_Final(rawMD5, &context);                  // Extract the final raw MD5
}

/*
 * Takes a filled raw md5 buffer and performs %4 on it.
 * return: int 0-3 that corresponds file storage schemes in table 1 in the writeup
 */
unsigned int MD5_to_pairs(unsigned char *rawMD5){
    unsigned int h1 = *((unsigned int*)rawMD5);     // Extract first 32 bits as h1
    unsigned int h2 = *((unsigned int*)rawMD5 + 4); // Extract next 32 bits as h2
    unsigned int h3 = *((unsigned int*)rawMD5 + 8); // ..
    unsigned int h4 = *((unsigned int*)rawMD5 + 12);

    unsigned int h = h1^h2^h3^h4; // XOR the 4 integers together into one

    return h%4; // Perform modulo 4 on the combined int and return
}

/*
 * Takes a raw md5 buffer and XORes all bytes together
 * return: a byte key based on the inputted MD5 for simple XOR encryption
 */
unsigned char MD5_to_key(unsigned char *rawMD5){
    unsigned char key = *(rawMD5);  // Extract the first byte
    for(int i = 1; i < MD5_DIGEST_LENGTH; i++){ // XOR last bytes together as a chain
        key = key ^ *(rawMD5 + i);
    }
    return key;
}

/*
 * Takes two raw MD5s and compares them
 * return: 1 on match, 0 on difference
 */
int compare_MD5s(unsigned char *rawMD5_1, unsigned char *rawMD5_2){
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++){ // Iterate through every MD5 byte
        if(rawMD5_1[i] != rawMD5_2[i]){         // If the two hashes don't match at i, break
            break;                              // Which will return 0 (no match)
        }else{                                  // If they do match
            if(i == MD5_DIGEST_LENGTH - 1){     // Check if it is the last byte
                return 1;                       // If so, return 1 (match)
            }
        }
    }
    return 0;
}

/*====================================================================================*/
/*====================================OTHER HELPERS===================================*/
/*====================================================================================*/

/*
 * Takes a short integer(0, 1, 2, 3) and converts it to (0 -> b'0001, 1 -> b'0010, 2 -> b'0100, 3 -> b'1000)
 * Returns a character with the corresponding flag set for the given index
 */
char block_index_to_flag(short index){
    index++; // Increment index from [0, 3] to [1, 4]
            // indices 1, 2 are now correct (0001 and 0010)
    index = index == 4 ? 8 : index; // 4 -> 1000 flag = 8
    index = index == 3 ? 4 : index; // 3 -> 0100 flag = 4
    char flag = 0;
    return flag | index;            // Or into char and return
}

/*
 * Calculates the file offset from SEEK_SET for a specific block and block sizes [4]
 * Sets *start to the offset of the block file
 */
void get_block_offsets(int block, int *sz_blocks, int *start){
    int off = 0;                     // Sum previous blocks to get offset to specified block
    for(int i = 0; i < block; i++){
        off+= sz_blocks[i];
    }
    *start = off;
}

/*
 * Takes an open "rb" file pointer, offset, length to sent, encryption key and socket to send to
 * Will read from file starting at offset for bytes_to_send bytes. if key != 0x00, byte will by encrypted first
 * Read bytes then sent to sock
 */
int send_file_tcp(FILE *file, long offset, long bytes_to_send, unsigned char key, int sock){
    fseek(file, offset, SEEK_SET); // moves file pointer to specified offset
    char fileBuffer[SZ_FILE_BUFF]; // Create large buffer to read into before sending
    int bytesLeft = bytes_to_send; // Counter down from # of bytes that must be read and sent
    while(bytesLeft > 0){          // While the full block hasn't been sent
        //printf("Sending with bytes left: %d\n", bytesLeft);
        memset(fileBuffer, 0, SZ_FILE_BUFF);
        // If we have to send bytes >= the size of our buffer, user the full buffer. Otherwise only use bytesLeft bytes of it
        int toRead = bytesLeft >= SZ_FILE_BUFF ? SZ_FILE_BUFF : bytesLeft;
        //printf("Will send: %d bytes.\n", toRead);
        int bytesRead = fread(fileBuffer, 1, toRead, file); // Read from the file
        //printf("Read %d bytes from disk.\n", bytesRead);
        if (key){                                                      // If encryption specified, XOR the bytes with the key
            xor_bytes(fileBuffer, bytesRead, key);
        }
        //printf("Xored file bytes before sending.\n");
        int sent = send(sock, fileBuffer, bytesRead, 0);                // Send the file bytes read
        //printf("Sent %d bytes.\n", sent);
        bytesLeft -= bytesRead;                                         // Reduce our counter by the bytes we read & sent

    }
    return 0;
}

/*
 * Takes a byte buffer, the buffer length, and an XOR key.
 * Performs XOR on the byte buffer of len with the passed key.
 */
void xor_bytes(unsigned char *bytes, unsigned int len, unsigned char key){
    for(int i = 0; i < len; i++) { // XOR each byte in place
        bytes[i] = bytes[i] ^ key;
    }
}

/*
 * Takes a c string and makes all characters lower in place
 * No return, edits the string in place
 */
void string_to_lower(char *str){
    if(str == NULL){ // Ensure string is valid
        return;
    }
    for(int i = 0; i < strlen(str); i++){ // Loop each character through tolower()
        str[i] = tolower(str[i]);
    }
}

/*
 * Takes two lines read from a cfg file containing a user and pass respectively
 * return: 1 on failure, 0 on success. Line buffers will hold parsed user/pass in place.
 */
int parse_username_pw(char *user_line, char *pw_line){
    if(user_line == NULL || pw_line == NULL){ // Check if 'User ' and 'Pass ' is present
        return 1;
    }
    if(strlen(user_line) < 6 || strlen(pw_line) < 6){
        return 1;
    }
    if(strncmp(user_line, "User ", 5) != 0 || strncmp(pw_line, "Pass ", 5) != 0 ){
        return 1;
    }

    user_line[strcspn(user_line, "\n")] = '\0'; // Remove newline character if present
    user_line[strcspn(user_line, "\r")] = '\0'; // Remove return character if present
    pw_line[strcspn(pw_line, "\n")] = '\0'; // Remove newline character if present
    pw_line[strcspn(pw_line, "\r")] = '\0'; // Remove return character if present

    // Copy user portion in place to beginning of buffer.
    memcpy(user_line, user_line + 5, strlen(user_line + 5) + 1); // Memcpy safe, wont overlap

    // Copy password portion in place to beginning of buffer.
    memcpy(pw_line, pw_line + 5, strlen(pw_line + 5) + 1); // Memcpy safe, wont overlap

    return 0;
}

#endif