# SEC Byzantine Fault Tolerant Banking

Our project allows several users to create bank accounts and perform transfers in a secure and reliable manner.
In addition to this, users are able to obtain transaction histories with the audit operation.
The system ensures authenticity and integrity.


## General Information

The system is composed of two main parts:
- **Client application:** allows clients to interact with the bank server and manage their accounts;
- **Primary Server:** is responsible for managing all accounts created by the clients and ensure the integrity of the accounts. The primary server is connected to a database, in order to store information of clients and accounts;
  

### Built With

This project uses certain technologies available, such as:

* [Java](https://openjdk.java.net/) - Programming Language and Platform
* [Maven](https://maven.apache.org/) - Build Tool and Dependency Management
* [Grpc](https://grpc.io/docs/languages/java/basics/) - Communication protocol
* [PostgreSQL](https://www.postgresql.org/) - Database Engine

## Getting Started

The following instructions will allow one to run the project on their local environment.

### Prerequisites

We recommend that you run this project on a computer with a linux distribution, such as Ubuntu 20.04 LTS.
The instructions shown in this tutorial were executed in a machine running the OS mentioned above.

#### Java

The java recommended version is 11. In order to install it, you must open a shell and run:
```shell
$ apt-get install openjdk-11-jdk
```

#### Maven

This project also relies on Maven. You can install the latest version, by running the following command:
```shell
$ apt-get install maven
```

#### PostgreSQL
Finally, you must install PostgreSQL, by running the following command:
```shell
$ apt-get install postgresql postgresql-contrib
```

This project relies on a database, so you must reset the postgres default database password through the postgreSQL command line. Run the following commands:
```shell
$ sudo -u postgres psql
psql>ALTER USER postgres PASSWORD "sec2022";
psql> \q
```


### Installing

You need to first clone the project to your local environment:
```shell
$ git@github.com:Larissa-Tomaz/SEC.git
```

After this, change your working directory to `SEC/`, which was just created:
```shell 
$ cd SEC/
```

You're now on the project's root directory. Therefore, you must install the maven dependencies and
compile the project's modules:
```shell
$ mvn clean install
```

The project is now compiled and all the dependencies are installed.
You will need to open two (or more) new terminals, in order to run the primary server
and an instance (or more) of the client application.


Start each server on a new terminal, we'll exemplify with 2 servers here:
```shell
$ cd server
$ mvn exec:java -Dexec.args="8090 R F B D" 
```
```shell
$ cd server
$ mvn exec:java -Dexec.args="8090 R1 F B D" 
```
R->Port of the replica

F->Max number of Byzantine faults, must be the same on all the servers

B->flag to set the server as Byzantine. 0->Normal 1->Byzantine

D->flag to clean the database. 0-does not clean 1->clean

***R and R1 need to be sequential***


Then, we can start one instance (or more) of the client, on a new terminal (or more):
```shell
$ cd client
$ mvn exec:java -Dexec.args="localhost 8090 F"
```
F->Max number of Byzantine faults, must be the same used on the servers

## Additional Information

### Authors

* **Rodrigo Gomes** - [rodrigo1110](https://github.com/rodrigo1110)
* **Marta Brites**  - [mabrites2210](https://github.com/mabrites2210)
* **Larissa Tomaz** - [Larissa-Tomaz](https://github.com/Larissa-Tomaz)

### License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

### Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.
