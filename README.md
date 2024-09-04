# LAKLAK-Multithreaded and Multiuser Application

 ### Socket Programming
 
In this project, I developed a messaging server and client using socket programming. In this system, there are multiple clients and a single server. Clients communicate with servers with LIST, LOGIN, LOGOUT, MSG, INFO and REGISTER commands.

1. LIST

o It is used to list the users on the server and their online/offline status.

o Usage: LIST [mask]

o mask * or ? Shows the listing mask created with

2. LOGIN

o Allows a user to log in to the system.

o Usage: LOGIN <user_name> <password> [mood]

- user_name: The user's name.

- password: The user's password.

- mood (optional): The user's current mood.

3. LOGOUT

o Allows the active user to log out of the system.

o Updates the user's state on the server and terminates the thread connected to that user.

4.MSG

o Sends a message to a specific user or all online users.

o Usage: MSG <user_name> <message>

- user_name: The name of the user to whom the message will be sent. If * is used, a message will be sent to all online users.

- message: The text of the message to be sent.

5. INFO

o Shows the name, surname and mood of the specified user.

o Usage: INFO <user_name>

- user_name: The name of the user whose information is requested.

6. REGISTER

o Allows a new user to register to the system.

o Usage: REGISTER <user_name> <password> <name-surname>

- user_name: The name of the new user.

- name: Name of the new user.

- surname: The new user's surname.

- password: The new user's password.
