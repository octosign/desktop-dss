#!/usr/bin/env bash

# Clear
rm -rf ./dist && mkdir ./dist

# Build the Maven project
mvn package -f pom.xml

# Copy files to dist directory
cp backend.yml ./dist/
cp LICENSE ./dist/
cp -r ./target/preparedJDK ./dist/jdk
cp -r ./target/dependency-jars ./dist/
cp ./target/octosigndss*.jar ./dist/sign.jar
