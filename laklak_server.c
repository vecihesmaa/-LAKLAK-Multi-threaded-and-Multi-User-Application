#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024
#define USER_FILE "users.txt"
#define GROUP_FILE "groups.txt"

// Engellenen kullanıcıları tutan yapı
typedef struct BlockedUser {
    char username[50];
    struct BlockedUser* next;
} BlockedUser;

typedef struct {
    char username[50];
    char password[50];
    char name[50];
    char surname[50];
    char mood[50];
    int is_online;
    SOCKET socket;
    BlockedUser* blocked_list;
} User;

typedef struct GroupMember {
    char username[50];
    struct GroupMember* next;
} GroupMember;

typedef struct {
    char group_name[50];
    char owner[50];
    GroupMember* members;
} Group;

User users[MAX_CLIENTS];
Group groups[MAX_CLIENTS];
int user_count = 0;
int group_count = 0;

void load_users() {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("Unable to open user file");
        exit(EXIT_FAILURE);
    }
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char* token = strtok(line, " ");
        if (token != NULL) strcpy(users[user_count].username, token);
        token = strtok(NULL, " ");
        if (token != NULL) strcpy(users[user_count].password, token);
        token = strtok(NULL, " ");
        if (token != NULL) strcpy(users[user_count].name, token);
        token = strtok(NULL, " ");
        if (token != NULL) strcpy(users[user_count].surname, token);
        token = strtok(NULL, " ");
        if (token != NULL) strcpy(users[user_count].mood, token);

        users[user_count].is_online = 0;
        users[user_count].blocked_list = NULL;

        // Engellenen kullanıcıları yükle
        while ((token = strtok(NULL, " \n")) != NULL) {
            BlockedUser* new_blocked = (BlockedUser*)malloc(sizeof(BlockedUser));
            strcpy(new_blocked->username, token);
            new_blocked->next = users[user_count].blocked_list;
            users[user_count].blocked_list = new_blocked;
        }
        user_count++;
    }
    fclose(file);
}

void save_users() {
    FILE *file = fopen(USER_FILE, "w");
    if (!file) {
        perror("Unable to open user file");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < user_count; i++) {
        fprintf(file, "%s %s %s %s %s", users[i].username, users[i].password, users[i].name, users[i].surname, users[i].mood);
        BlockedUser* current = users[i].blocked_list;
        while (current != NULL) {
            fprintf(file, " %s", current->username);
            current = current->next;
        }
        fprintf(file, "\n");
    }
    fclose(file);
}

// Kullanıcı engelleme fonksiyonu
void block_user(User* user, const char* blocked_username) {
    BlockedUser* new_blocked = (BlockedUser*)malloc(sizeof(BlockedUser));
    strcpy(new_blocked->username, blocked_username);
    new_blocked->next = user->blocked_list;
    user->blocked_list = new_blocked;
    save_users(); // Engelleme bilgisini hemen kaydet   
}

// Kullanıcıyı engelleyen fonksiyon
int is_blocked(User* user, const char* username) {
    BlockedUser* current = user->blocked_list;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

void unblock_user(User* user, const char* blocked_username) {
    BlockedUser* current = user->blocked_list;
    BlockedUser* prev = NULL;

    while (current != NULL) {
        if (strcmp(current->username, blocked_username) == 0) {
            if (prev == NULL) {
                user->blocked_list = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            save_users();
            return;
        }
        prev = current;
        current = current->next;
    }
}

void list_blocked_users(User* user, SOCKET client_socket) {
    BlockedUser* current = user->blocked_list;
    char response[BUFFER_SIZE] = "Blocked users:\n";
    while (current != NULL) {
        strcat(response, current->username);
        strcat(response, "\n");
        current = current->next;
    }
    send(client_socket, response, strlen(response), 0);
}

void load_groups() {
    FILE *file = fopen(GROUP_FILE, "r");
    if (!file) {
        perror("Unable to open group file");
        exit(EXIT_FAILURE);
    }
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char* token = strtok(line, " ");
        if (token != NULL) strcpy(groups[group_count].group_name, token);
        token = strtok(NULL, " ");
        if (token != NULL) strcpy(groups[group_count].owner, token);

        groups[group_count].members = NULL;
        while ((token = strtok(NULL, " \n")) != NULL) {
            GroupMember* new_member = (GroupMember*)malloc(sizeof(GroupMember));
            strcpy(new_member->username, token);
            new_member->next = groups[group_count].members;
            groups[group_count].members = new_member;
        }
        group_count++;
    }
    fclose(file);
}

void save_groups() {
    FILE *file = fopen(GROUP_FILE, "w");
    if (!file) {
        perror("Unable to open group file");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < group_count; i++) {
        fprintf(file, "%s %s", groups[i].group_name, groups[i].owner);
        GroupMember* current = groups[i].members;
        while (current != NULL) {
            fprintf(file, " %s", current->username);
            current = current->next;
        }
        fprintf(file, "\n");
    }
    fclose(file);
}

void add_to_group(const char* group_name, const char* username) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].group_name, group_name) == 0) {
            GroupMember* new_member = (GroupMember*)malloc(sizeof(GroupMember));
            strcpy(new_member->username, username);
            new_member->next = groups[i].members;
            groups[i].members = new_member;
            save_groups();
            break;
        }
    }
}


void create_group(const char* group_name, const char* owner) {
    strcpy(groups[group_count].group_name, group_name);
    strcpy(groups[group_count].owner, owner);
    groups[group_count].members = NULL;
    group_count++;
    save_groups();
}

void broadcast_group_message(const char* group_name, const char* message, const char* sender) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].group_name, group_name) == 0) {
            GroupMember* current = groups[i].members;
            while (current != NULL) {
                for (int j = 0; j < user_count; j++) {
                    if (strcmp(users[j].username, current->username) == 0 && users[j].is_online) {
                        send(users[j].socket, message, strlen(message), 0);
                    }
                }
                current = current->next;
            }
            break;
        }
    }
}

void broadcast_message(const char* message, const char* sender, SOCKET exclude_socket) {
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_online && users[i].socket != exclude_socket && !is_blocked(&users[i], sender)) {
            send(users[i].socket, message, strlen(message), 0);
        }
    }
}

DWORD WINAPI handle_client(LPVOID arg) {
    SOCKET client_socket = *(SOCKET *)arg;
    char buffer[BUFFER_SIZE];
    char username[50];
    char mood[50] = "";
    int logged_in = 0;

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            closesocket(client_socket);
            break;
        }

        // Process commands
        char command[10];
        sscanf(buffer, "%s", command);

        if (strcmp(command, "REGISTER") == 0) {
            char password[50], name[50], surname[50];
            sscanf(buffer, "REGISTER %s %s %s %s", username, password, name, surname);
            strcpy(users[user_count].username, username);
            strcpy(users[user_count].password, password);
            strcpy(users[user_count].name, name);
            strcpy(users[user_count].surname, surname);
            strcpy(users[user_count].mood, ""); // Default mood
            users[user_count].is_online = 0;
            users[user_count].blocked_list = NULL;
            user_count++;
            save_users();
            send(client_socket, "Registration successful\n", 24, 0);
        } else if (strcmp(command, "LOGIN") == 0) {
            char password[50];
            sscanf(buffer, "LOGIN %s %s %s", username, password,mood);
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, username) == 0 && strcmp(users[i].password, password) == 0) {
                    users[i].is_online = 1;
                    users[i].socket = client_socket;
                    logged_in = 1;
                    strcpy(users[i].mood, mood);
                    send(client_socket, "Login successful\n", 18, 0);
                    break;
                }
            }
            if (!logged_in) {
                send(client_socket, "Login failed\n", 13, 0);
            }
        } else if (strcmp(command, "LOGOUT") == 0) {
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, username) == 0) {
                    users[i].is_online = 0;
                    logged_in = 0;
                    send(client_socket, "Logout successful\n", 19, 0);
                    closesocket(client_socket);
                    return 0;
                }
            }
        } else if (strcmp(command, "LIST") == 0) {
            char response[BUFFER_SIZE] = "";
            for (int i = 0; i < user_count; i++) {
                char user_info[100];
                sprintf(user_info, "%s %s\n", users[i].username, users[i].is_online ? "online" : "offline");
                strcat(response, user_info);
            }
            send(client_socket, response, strlen(response), 0);
        } else if (strcmp(command, "MSG") == 0) {
            char recipient[50], message[BUFFER_SIZE], messageInformation[BUFFER_SIZE];
            sscanf(buffer, "MSG %s %[^\n]", recipient, message);
            sprintf(messageInformation,"Message from %s : ", username);
            strcat(messageInformation,message);
            if (strcmp(recipient, "*") == 0) {
                broadcast_message(messageInformation, username, client_socket);
            } else {
                for (int i = 0; i < user_count; i++) {
                    if (strcmp(users[i].username, recipient) == 0 && users[i].is_online && !is_blocked(&users[i], username)) {
                        send(users[i].socket, messageInformation, strlen(messageInformation), 0);
                        break;
                    }
                }
            }
        } else if (strcmp(command, "INFO") == 0) {
            char target[50];
            sscanf(buffer, "INFO %s", target);
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, target) == 0) {
                    char user_info[100];
                    sprintf(user_info, "Name: %s %s, Mood: %s\n", users[i].name, users[i].surname, users[i].mood);
                    send(client_socket, user_info, strlen(user_info), 0);
                    break;
                }
            }
        } else if (strcmp(command, "BLOCK") == 0) {
            char blocked_username[50];
            sscanf(buffer, "BLOCK %s", blocked_username);
            if (strcmp(username,blocked_username) != 0)
            {
                for (int i = 0; i < user_count; i++) {
                    if (strcmp(users[i].username, username) == 0) {
                        block_user(&users[i], blocked_username);
                        send(client_socket, "User blocked\n", 13, 0);
                        break;
                    }
                }              
            }else{
                send(client_socket, "You can't block yourself\n", 25, 0);
            }
            
        }else if (strcmp(command, "UNBLOCK") == 0) {
            char unblocked_username[50];
            sscanf(buffer, "UNBLOCK %s", unblocked_username);
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, username) == 0) {
                    unblock_user(&users[i], unblocked_username);
                    send(client_socket, "User unblocked\n", 15, 0);
                    break;
                }
            } 
        }else if (strcmp(command, "BLOCKED_LIST") == 0) {
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, username) == 0) {
                    list_blocked_users(&users[i], client_socket);
                    break;
                }
            }
        }else if (strcmp(command, "CREATE_GROUP") == 0) {
            char group_name[50];
            sscanf(buffer, "CREATE_GROUP %s", group_name);
            create_group(group_name, username);
            send(client_socket, "Group created\n", 14, 0);
        } else if (strcmp(command, "ADD_TO_GROUP") == 0) {
            char group_name[50], member[50];
            sscanf(buffer, "ADD_TO_GROUP %s %s", group_name, member);
            add_to_group(group_name, member);
            send(client_socket, "Member added to group\n", 22, 0);
        } else if (strcmp(command, "MSG_GROUP") == 0) {
            char group_name[50], msg[BUFFER_SIZE];
            sscanf(buffer, "MSG_GROUP %s %[^\n]", group_name, msg);
            broadcast_group_message(group_name, msg, username);
        }else if (strcmp(command, "MOOD") == 0) {
            char new_mood[50];
            sscanf(buffer, "MOOD %s", new_mood);
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, username) == 0) {
                    strcpy(users[i].mood, new_mood);
                    save_users();
                    send(client_socket, "Mood updated\n", 13, 0);
                    break;
                }
            }
        }else if (strcmp(command, "HELP") == 0) {
            char help_message[BUFFER_SIZE];
            sprintf(help_message,  "--------------------------------------------------\n"
                                   "Available commands:\n"
                                   "*** REGISTER <username> <password> <name> <surname>\n"
                                   "*** LOGIN <username> <password> <mood>\n"
                                   "*** LOGOUT\n"
                                   "*** LIST\n"
                                   "*** MSG <recipient> <message>\n"
                                   "*** INFO <username>\n"
                                   "*** BLOCK <username>\n"
                                   "*** UNBLOCK <usernanme>\n"
                                   "*** BLOCKED_LIST\n"
                                   "*** CREATE_GROUP <group_name>\n"
                                   "*** ADD_TO_GROUP <group_name> <username>\n"
                                   "*** MSG_GROUP <group_name> <message>\n"
                                   "*** MOOD <new mood>\n"
                                   "*** HELP\n"
                                   "--------------------------------------------------\n");
            send(client_socket, help_message, strlen(help_message), 0);
        } else {
            send(client_socket, "Unknown command\n", 16, 0);
        }
    }

    closesocket(client_socket);
    return 0;
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int addr_size = sizeof(struct sockaddr_in);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("Bind failed");
        closesocket(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) == SOCKET_ERROR) {
        perror("Listen failed");
        closesocket(server_socket);
        exit(EXIT_FAILURE);
    }

    load_users();
    load_groups();

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_size);
        if (client_socket == INVALID_SOCKET) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected\n");

        DWORD tid;
        CreateThread(NULL, 0, handle_client, (void *)&client_socket, 0, &tid);
    }

    closesocket(server_socket);
    WSACleanup();
    return 0;
}