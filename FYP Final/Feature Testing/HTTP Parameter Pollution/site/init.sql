CREATE DATABASE hpp_test_db;

USE hpp_test_db;

CREATE TABLE users (
    id int NOT NULL AUTO_INCREMENT,
    username varchar(255) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO users(username) VALUES("Bob");
INSERT INTO users(username) VALUES("John");
INSERT INTO users(username) VALUES("Sam");
INSERT INTO users(username) VALUES("Tim");