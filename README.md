# Java-UDP-socket-programming


There are 2 folders - ClientSide and Serverside
Bob alphanumeric password : six666

ServerSide(2 java files):

1) SetUpAliceBob.java, this file was used to generate the diffie hellman parameters.By executing this file you will generate P,G and H(PW) values as well as
sending a txt file(dhParameters.txt) containing (P,G,HW) for AliceHost.java

2) AliceHost.java is the UDP host file

ClientSide:
1)BobClient is the UDP client file

***HOW TO RUN THE FILE***
-Open cmd terminal and cd to "\NetworkSecurity_A1\ServerSide" 

-Compile and Run SetUpAliceBob.java(dhParameter.txt should appear in the ServerSide directory)

-Compile and Run AliceHost.java(Alice(Host) is ONLINE should appear)

-Open another cmd terminal and cd to "\NetworkSecurity_A1\ClientSide"

-Compile and Run BobClient.java

-Upon prompt of password enter, six666

-After display of handshake detail, a prompt to "enter message " will appear, this means you can being communicating with Alice(Host) and
your message will be reflected on Alice(host) terminal.Vice versa on Alice's end

-To terminate the connection type "exit"

sources used:
for DH parameters(for generator values) -->> https://github.com/bhepburn/CS789/tree/master/src/functions  
for RC4 encryption -->> https://github.com/engFathalla/RC4-Algorithm/blob/master/RC4/src/encryption/RC4.java
