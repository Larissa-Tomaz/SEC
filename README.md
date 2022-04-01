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

This project relies on a database, so you must create one through the postgreSQL command line. Run the following commands:
```shell
$ su -- postgres
$ psql
psql> CREATE DATABASE bankingservice;
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

It is important to outline that the primary server **must be started before** the client.
Let's focus on the primary server now.

You need to set 4 environment variables which will be used by the primary server, in order to connect to the database:
```shell
$ export DB_URL=jdbc:postgresql://localhost:5432/bankingservice
$ export DB_USERNAME=postgres
$ export DB_PASSWORD=<The password for this user>
$ export DB_DIR=<The path to the schema/schema.sql file>
```

Once this is done, we can start the primary server, on a new terminal:
```shell
$ cd server
$ mvn exec:java
```

Then, we can start one instance (or more) of the client, on a new terminal (or more):
```shell
$ cd client
$ mvn exec:java
```

### Testing

Explain how to run the automated tests for this system.

Give users explicit instructions on how to run all necessary tests.
Explain the libraries, such as JUnit, used for testing your software and supply all necessary commands.

Explain what these tests test and why

```
Give an example command
```

## Demo

Give a tour of the best features of the application.
Add screenshots when relevant.

## Deployment

In order to host the system in a live environment, there are some adjustments to be made.

### Primary Server
Change the environment variables with the details of the production environment:
- Location of the database (host and port);
- Username and password to access the database.

Furthermore, the primary server's pom.xml file must be changed.

### Client
The client's pom.xml file must be changed as well, accordingly. The `server.host` and `server.port` properties
must be changed to the ones where the primary server is running on.

## Additional Information

### Authors

* **Rodrigo Gomes** - [rodrigo1110](https://github.com/rodrigo1110)
* **Marta Brites** 
* **Larissa Tomaz** - [Larissa-Tomaz](https://github.com/Larissa-Tomaz)

### License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

### Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.
